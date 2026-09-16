import json
import logging
import re
import requests
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
EXPLICIT_VPN_PATTERN = re.compile(
    r'(?:vpn|впн|ovpn|openvpn|wg|wireguard|туннель|tunnel|ip\s*vpn|vpn\s*ip|ip)[:=\s\-]*(' + IPV4_REGEX + r')',
    re.IGNORECASE
)
IP_PORT_PATTERN = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):([0-9]{2,5})\b'
)
EXPLICIT_PORT_PATTERN = re.compile(
    r'(?:ssh[\s_-]*port|порт|port|ssh)[:=\s\-]+([0-9]{2,5})\b',
    re.IGNORECASE
)

def extract_vpn_ip_from_comment(comment: Optional[str]) -> Optional[str]:
    """
    Extracts a VPN IPv4 address from Zabbix host comment (description).
    Checks explicit keywords first ('VPN: 10.x.x.x', 'впн 10.x.x.x', etc.),
    then checks if any valid IPv4 address is present in the comment.
    Ignores loopback, broadcast, or zero IPs.
    """
    if not comment:
        return None

    # 1. Search with explicit prefixes
    match = EXPLICIT_VPN_PATTERN.search(comment)
    if match:
        ip = match.group(1).strip()
        if not ip.startswith(("127.", "0.", "255.")):
            return ip

    return None


def extract_port_from_comment(comment: Optional[str]) -> Optional[int]:
    """
    Extracts custom SSH port from Zabbix host comment (description).
    Matches patterns like '10.0.0.10:2222', 'порт: 2222', 'port 2222', 'ssh port: 2222'.
    Validates port is within 1..65535. Returns int or None.
    """
    if not comment:
        return None

    # 1. IP:PORT pattern (e.g. 10.0.0.10:2222)
    m = IP_PORT_PATTERN.search(comment)
    if m:
        try:
            port = int(m.group(1))
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass

    # 2. Explicit keywords: 'порт 2222', 'port: 2222', 'ssh port 2222'
    m = EXPLICIT_PORT_PATTERN.search(comment)
    if m:
        try:
            port = int(m.group(1))
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass

    return None

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
        headers = {
            "Content-Type": "application/json-rpc"
        }

        # Zabbix 6.4/7.0 strictly requires apiinfo.version to be unauthenticated
        if method != "apiinfo.version" and self.token:
            payload["auth"] = self.token
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
            "output": ["hostid", "host", "name", "status", "description", "proxy_hostid"],
            "filter": {"status": "0"},
            "selectInterfaces": ["ip", "dns", "useip", "main", "type"],
            "selectParentTemplates": ["templateid", "name"],
            "selectGroups": ["groupid", "name"]
        })

        return groups_raw or [], hosts_raw or []

    def create_host(self, host_name: str, ip_address: str, group_id: str, port: int = 10050, proxy_hostid: Optional[str] = None, template_name: str = "Linux by Zabbix agent") -> dict:
        """Creates a new host in Zabbix via host.create API."""
        templates_payload = []
        try:
            tmpl_res = self._call("template.get", {
                "output": ["templateid", "name"],
                "filter": {"name": [template_name, "Linux by Zabbix agent", "Windows by Zabbix agent"]}
            })
            if tmpl_res:
                templates_payload.append({"templateid": tmpl_res[0]["templateid"]})
        except Exception as e:
            logger.warning(f"Failed to fetch template {template_name}: {e}")

        interface_data = {
            "type": 1,
            "main": 1,
            "useip": 1,
            "ip": ip_address,
            "dns": "",
            "port": str(port)
        }

        params = {
            "host": host_name,
            "name": host_name,
            "interfaces": [interface_data],
            "groups": [{"groupid": str(group_id)}],
            "status": 0
        }
        if templates_payload:
            params["templates"] = templates_payload
        if proxy_hostid and str(proxy_hostid) not in ("0", ""):
            params["proxy_hostid"] = str(proxy_hostid)

        return self._call("host.create", params)



NETWORK_KEYWORDS = [
    "tp-link", "tplink", "cisco", "mikrotik", "routeros", "keenetic",
    "d-link", "dlink", "zyxel", "eltex", "huawei", "juniper", "fortigate",
    "fortinet", "ubiquiti", "unifi", "edgerouter", "netgear", "aruba",
    "switch", "router", "коммутатор", "роутер", "маршрутизатор", "свитч"
]
LINUX_NAME_PATTERN = re.compile(r'(?:^|[_\-.])(?:deb|ubn|ubuntu|centos|rhel|debian|lin)(?:[_\-.\d]|$)', re.IGNORECASE)
WINDOWS_NAME_PATTERN = re.compile(r'(?:^|[_\-.])(?:win|dc|rds|srv-win)(?:[_\-.\d]|$)', re.IGNORECASE)
NETWORK_NAME_PATTERN = re.compile(r'(?:^|[_\-.])(?:sw|rt|switch|router|tplink|tp-link|dlink|d-link|mikrotik|cisco|keenetic|zyxel|eltex|ap|gw)(?:[_\-.\d]|$)', re.IGNORECASE)

def detect_os_type(template_names: list, host_name: str = "") -> str:
    """
    Heuristic to detect OS or device type from Zabbix templates and host names.
    Returns: 'linux', 'windows', 'network', or 'unknown'.
    """
    t_lower = " ".join([t.lower() for t in template_names])
    h_lower = host_name.lower()

    # 1. Check explicit official Zabbix Agent templates
    if "windows by" in t_lower or "windows agent" in t_lower:
        return "windows"
    if "linux by" in t_lower or "linux agent" in t_lower or "linux generic" in t_lower:
        return "linux"

    # 2. Check network equipment templates (SNMP, Switches, Routers, TP-Link, MikroTik, Cisco)
    if any(k in t_lower for k in NETWORK_KEYWORDS):
        return "network"

    # 3. Check general OS keywords in templates
    if "windows" in t_lower or "win by" in t_lower:
        return "windows"
    if any(l in t_lower for l in ["linux", "unix", "ubuntu", "centos", "debian", "redhat", "rhel"]):
        return "linux"

    # 4. Check host name heuristics with safe boundary patterns (avoids tp-link matching -lin)
    if any(k in h_lower for k in NETWORK_KEYWORDS) or NETWORK_NAME_PATTERN.search(host_name):
        return "network"
    if WINDOWS_NAME_PATTERN.search(host_name):
        return "windows"
    if LINUX_NAME_PATTERN.search(host_name):
        return "linux"

    return "unknown"


def detect_equipment_type(template_names: list, host_name: str = "", description: str = "") -> Tuple[bool, str]:
    """
    Detects if a host is non-standard equipment (iDRAC, IPMI, iLO, Synology NAS, Network switch, UPS, Printer)
    that should not be probed via SSH / Ansible tasks.
    Returns: (is_ignored: bool, device_type: str)
      device_type can be: 'server', 'idrac_ipmi', 'nas', 'network', 'ups', 'printer', 'other'
    """
    t_lower = " ".join([t.lower() for t in template_names])
    h_lower = host_name.lower()
    d_lower = (description or "").lower()
    combined = f"{t_lower} {h_lower} {d_lower}"

    # 1. iDRAC, IPMI, iLO, IMM, BMC
    if any(k in t_lower or k in h_lower for k in ["idrac", "ipmi", "ilo", "bmc", "imm"]):
        return True, "idrac_ipmi"

    # 2. NAS / Storage (Synology, QNAP, TrueNAS, etc.)
    if any(k in combined for k in ["synology", "diskstation", "qnap", "truenas", "freenas", "asustor", "netapp"]):
        return True, "nas"
    if re.search(r'(?:^|[_\-.])nas(?:[_\-.\d]|$)', h_lower) or "_nas" in h_lower or "-nas" in h_lower:
        return True, "nas"

    # 3. UPS / PDU
    if any(k in combined for k in ["smart-ups", "eaton", "cyberpower", "powercom", "liebert"]) or (
        ("apc" in h_lower or "ups" in h_lower) and not ("linux" in t_lower or "windows" in t_lower)
    ):
        return True, "ups"

    # 4. Printers / MFPs
    if any(k in combined for k in ["kyocera", "xerox", "ricoh", "konica"]) or (
        "printer" in combined and not ("linux" in t_lower or "windows" in t_lower)
    ):
        return True, "printer"

    # 5. Network equipment (Switches, Routers, Firewalls)
    if any(k in t_lower for k in NETWORK_KEYWORDS) or (
        any(k in h_lower for k in NETWORK_KEYWORDS) and not ("linux" in t_lower or "windows" in t_lower)
    ):
        return True, "network"

    # Default: regular server
    return False, "server"



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
    network_count = 0
    unknown_count = 0
    vpn_count = 0
    manual_ip_count = 0
    manual_os_count = 0
    custom_port_count = 0

    for h_data in hosts_raw:
        hid = str(h_data["hostid"])
        seen_hostids.add(hid)
        hname = h_data.get("name") or h_data.get("host")
        description = (h_data.get("description") or "").strip()
        proxy_hostid = str(h_data.get("proxy_hostid") or "0")
        
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

        # Check for VPN IP and SSH port in host description/comment
        vpn_ip = extract_vpn_ip_from_comment(description)
        vpn_port = extract_port_from_comment(description)
        effective_ip = vpn_ip if vpn_ip else ip
        effective_source = "vpn_comment" if vpn_ip else "zabbix"

        # Templates & OS detection
        templates = h_data.get("parentTemplates", [])
        template_names = [t.get("name", "") for t in templates]
        os_type = detect_os_type(template_names, hname)

        if os_type == "linux":
            linux_count += 1
        elif os_type == "windows":
            windows_count += 1
        elif os_type == "network":
            network_count += 1
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
            host.zabbix_agent_ip = ip
            host.zabbix_description = description
            host.proxy_hostid = proxy_hostid

            # Only overwrite IP/port if it was NOT manually set by user
            if host.is_ip_manually_set:
                manual_ip_count += 1
                host.ip_source = "manual"
            else:
                host.ip_address = effective_ip
                host.ip_source = effective_source
                if vpn_ip:
                    vpn_count += 1
                # Update SSH port if detected in comment and not manually locked
                if vpn_port:
                    host.ssh_port = vpn_port

            if host.ssh_port and host.ssh_port != 22:
                custom_port_count += 1

            # Keep manual override if set, otherwise update detected OS
            if host.is_os_manually_set:
                manual_os_count += 1
            else:
                if host.os_type in ("unknown", None) or os_type != "unknown":
                    host.os_type = os_type
            host.zabbix_templates = ", ".join(template_names)
            if primary_group_id:
                host.group_id = primary_group_id
            host.is_enabled = True

            # Equipment auto-detection (iDRAC, IPMI, NAS, Network, UPS)
            is_eq, eq_type = detect_equipment_type(template_names, hname, description)
            if not getattr(host, "is_ignored_manually_set", False):
                host.is_ignored = is_eq
                host.device_type = eq_type
        else:
            if vpn_ip:
                vpn_count += 1
            if vpn_port and vpn_port != 22:
                custom_port_count += 1

            is_eq, eq_type = detect_equipment_type(template_names, hname, description)
            host = Host(
                zabbix_hostid=hid,
                name=hname,
                ip_address=effective_ip,
                ssh_port=vpn_port,
                is_ip_manually_set=False,
                is_os_manually_set=False,
                is_ignored=is_eq,
                is_ignored_manually_set=False,
                device_type=eq_type,
                ip_source=effective_source,
                zabbix_agent_ip=ip,
                zabbix_description=description,
                proxy_hostid=proxy_hostid,
                os_type=os_type,
                zabbix_templates=", ".join(template_names),
                group_id=primary_group_id,
                is_enabled=True,
                last_status="unknown"
            )
            db_session.add(host)

    # Disable hosts that were removed or unmonitored in Zabbix (do not disable manual non-Zabbix hosts)
    for hid, host in existing_hosts.items():
        if hid not in seen_hostids:
            if not str(hid).startswith("manual_"):
                host.is_enabled = False

    # Update ZabbixSetting status
    now = datetime.utcnow()
    total_hosts = len(seen_hostids)
    extra_details = []
    if vpn_count > 0:
        extra_details.append(f"VPN из описания: {vpn_count}")
    if manual_ip_count > 0:
        extra_details.append(f"Ручных IP: {manual_ip_count}")
    if manual_os_count > 0:
        extra_details.append(f"Ручных ОС: {manual_os_count}")
    if custom_port_count > 0:
        extra_details.append(f"Кастомных портов SSH: {custom_port_count}")
    extra_str = f" | {', '.join(extra_details)}" if extra_details else ""
    msg = f"Синхронизировано групп: {len(zabbix_group_map)}, хостов: {total_hosts} (Linux: {linux_count}, Windows: {windows_count}, Сеть: {network_count}, Прочие: {unknown_count}{extra_str})"
    
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
