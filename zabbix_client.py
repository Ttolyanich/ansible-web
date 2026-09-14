import json
import logging
import requests
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class ZabbixAPIError(Exception):
    pass

class ZabbixClient:
    def __init__(self, url: str, token: str, verify_ssl: bool = False, timeout: int = 15):
        self.url = url.rstrip("/")
        if not self.url.endswith("api_jsonrpc.php"):
            self.url = f"{self.url}/api_jsonrpc.php"
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.req_id = 1

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.req_id
        }
        if self.token:
            payload["auth"] = self.token

        headers = {
            "Content-Type": "application/json-rpc"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        self.req_id += 1
        try:
            resp = requests.post(
                self.url,
                json=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                err_msg = data["error"].get("data") or data["error"].get("message")
                raise ZabbixAPIError(f"Zabbix API Error: {err_msg}")
            return data.get("result")
        except requests.exceptions.RequestException as e:
            raise ZabbixAPIError(f"Network error connecting to Zabbix: {str(e)}")

    def test_connection(self) -> Tuple[bool, str]:
        """Test URL and Token validity."""
        try:
            version = self._call("apiinfo.version")
            # Verify auth token by fetching 1 group
            groups = self._call("hostgroup.get", {"limit": 1})
            return True, f"Успешное подключение! Версия Zabbix API: {version}"
        except Exception as e:
            return False, str(e)

    def fetch_inventory(self) -> Tuple[list, list]:
        """Fetch all hostgroups and active hosts with templates and interfaces."""
        # 1. Fetch host groups
        groups_raw = self._call("hostgroup.get", {
            "output": ["groupid", "name"],
            "real_hosts": True # only groups containing real hosts
        })

        # 2. Fetch hosts (only enabled hosts: status=0)
        hosts_raw = self._call("host.get", {
            "output": ["hostid", "host", "name", "status"],
            "filter": {"status": "0"},
            "selectInterfaces": ["ip", "dns", "useip", "main", "type"],
            "selectParentTemplates": ["templateid", "name"],
            "selectGroups": ["groupid", "name"]
        })

        return groups_raw or [], hosts_raw or []


def detect_os_type(template_names: list, host_name: str = "") -> str:
    """Heuristic to detect OS from Zabbix templates."""
    t_lower = " ".join([t.lower() for t in template_names])
    if "windows" in t_lower or "win by" in t_lower:
        return "windows"
    if "linux" in t_lower or "linux by" in t_lower or "unix" in t_lower or "ubuntu" in t_lower or "centos" in t_lower or "debian" in t_lower:
        return "linux"
    
    # Fallback to host name heuristic
    h_lower = host_name.lower()
    if any(win_tag in h_lower for win_tag in ["-win", "win-", "_win", "win_", "dc0", "rds"]):
        return "windows"
    if any(lin_tag in h_lower for lin_tag in ["-deb", "-ubn", "-centos", "-lin", "lin-", "_lin"]):
        return "linux"
        
    return "unknown"


def sync_zabbix_to_db(db_session, zabbix_setting, user_id: Optional[int] = None) -> Tuple[bool, str, dict]:
    """Execute full sync from Zabbix API into local database."""
    from models import HostGroup, Host, TaskJob, AuditLog

    if not zabbix_setting.url or not zabbix_setting.token:
        return False, "Не настроены URL или токен Zabbix API", {}

    client = ZabbixClient(zabbix_setting.url, zabbix_setting.token, verify_ssl=zabbix_setting.verify_ssl)

    try:
        groups_raw, hosts_raw = client.fetch_inventory()
    except Exception as e:
        zabbix_setting.last_sync_status = "error"
        zabbix_setting.last_sync_message = str(e)
        zabbix_setting.last_sync_at = datetime.utcnow()
        db_session.commit()
        return False, f"Ошибка синхронизации: {str(e)}", {}

    # 1. Sync Groups
    existing_groups = {g.zabbix_groupid: g for g in HostGroup.query.all()}
    zabbix_group_map = {} # zabbix_groupid -> DB HostGroup object

    for g_data in groups_raw:
        gid = str(g_data["groupid"])
        gname = g_data["name"]
        if gid in existing_groups:
            group = existing_groups[gid]
            group.name = gname
        else:
            group = HostGroup(zabbix_groupid=gid, name=gname)
            db_session.add(group)
            db_session.flush()
        zabbix_group_map[gid] = group

    # 2. Sync Hosts
    existing_hosts = {h.zabbix_hostid: h for h in Host.query.all()}
    seen_hostids = set()

    linux_count = 0
    windows_count = 0
    unknown_count = 0

    for h_data in hosts_raw:
        hid = str(h_data["hostid"])
        seen_hostids.add(hid)
        hname = h_data.get("name") or h_data.get("host")
        
        # Pick IP address: look for main interface (main=1)
        interfaces = h_data.get("interfaces", [])
        ip = "127.0.0.1"
        if interfaces:
            main_iface = next((i for i in interfaces if str(i.get("main")) == "1"), interfaces[0])
            if str(main_iface.get("useip")) == "1" and main_iface.get("ip"):
                ip = main_iface["ip"]
            elif main_iface.get("dns"):
                ip = main_iface["dns"]
            else:
                ip = main_iface.get("ip") or "127.0.0.1"

        # Templates & OS detection
        templates = h_data.get("parentTemplates", [])
        template_names = [t.get("name", "") for t in templates]
        os_type = detect_os_type(template_names, hname)

        if os_type == "linux":
            linux_count += 1
        elif os_type == "windows":
            windows_count += 1
        else:
            unknown_count += 1

        # Determine primary group (first matched group)
        host_groups = h_data.get("groups", [])
        primary_group_id = None
        if host_groups:
            first_gid = str(host_groups[0]["groupid"])
            if first_gid in zabbix_group_map:
                primary_group_id = zabbix_group_map[first_gid].id

        if hid in existing_hosts:
            host = existing_hosts[hid]
            host.name = hname
            host.ip_address = ip
            # Keep manual override if set, otherwise update detected OS
            if host.os_type in ("unknown", None) or os_type != "unknown":
                host.os_type = os_type
            host.zabbix_templates = ", ".join(template_names)
            if primary_group_id:
                host.group_id = primary_group_id
            host.is_enabled = True
        else:
            host = Host(
                zabbix_hostid=hid,
                name=hname,
                ip_address=ip,
                os_type=os_type,
                zabbix_templates=", ".join(template_names),
                group_id=primary_group_id,
                is_enabled=True,
                last_status="unknown"
            )
            db_session.add(host)

    # Disable hosts that were removed or unmonitored in Zabbix
    for hid, host in existing_hosts.items():
        if hid not in seen_hostids:
            host.is_enabled = False

    # Update ZabbixSetting status
    now = datetime.utcnow()
    total_hosts = len(seen_hostids)
    msg = f"Синхронизировано групп: {len(zabbix_group_map)}, хостов: {total_hosts} (Linux: {linux_count}, Windows: {windows_count}, Прочие: {unknown_count})"
    
    zabbix_setting.last_sync_status = "success"
    zabbix_setting.last_sync_message = msg
    zabbix_setting.last_sync_count = total_hosts
    zabbix_setting.last_sync_at = now

    audit = AuditLog(
        user_id=user_id,
        action="ZABBIX_SYNC",
        target="Zabbix API",
        description=msg
    )
    db_session.add(audit)
    db_session.commit()

    stats = {
        "groups": len(zabbix_group_map),
        "total_hosts": total_hosts,
        "linux": linux_count,
        "windows": windows_count,
        "unknown": unknown_count
    }
    return True, msg, stats
