import os
import sys
import json
import yaml
import shutil
import tempfile
import subprocess
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Background executor for tasks
executor = ThreadPoolExecutor(max_workers=4)

def resolve_credentials(host, db_session) -> Dict[str, Any]:
    """
    Resolve credentials hierarchy:
    1. Host individual override
    2. Group override
    3. Global OS default profile
    """
    from models import CredentialProfile

    profile = None
    if host.override_credential:
        profile = host.override_credential
    elif host.group and host.group.credential:
        profile = host.group.credential
    else:
        profile = CredentialProfile.query.filter_by(os_type=host.os_type, is_default=True).first()

    creds = {
        "user": "root" if host.os_type == "linux" else "ITSGSRV",
        "port": 22,
        "auth_type": "key",
        "private_key": "",
        "passphrase": "",
        "password": "",
        "sudo_password": "",
        "become_method": "sudo" if host.os_type == "linux" else "none"
    }

    if profile:
        creds["user"] = profile.ssh_user or creds["user"]
        creds["port"] = profile.ssh_port or 22
        creds["auth_type"] = profile.auth_type or "key"
        creds["private_key"] = profile.private_key or ""
        creds["passphrase"] = profile.passphrase or ""
        creds["password"] = profile.password or ""
        creds["sudo_password"] = profile.sudo_password or ""
        creds["become_method"] = profile.become_method or creds["become_method"]

    return creds


def generate_inventory(hosts: list, temp_dir: str, db_session) -> str:
    """Generate YAML inventory file with resolved credentials and SSH options."""
    inventory_data = {
        "all": {
            "hosts": {}
        }
    }

    keys_dir = os.path.join(temp_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    for host in hosts:
        creds = resolve_credentials(host, db_session)
        host_vars = {
            "ansible_host": host.ip_address,
            "ansible_port": creds["port"],
            "ansible_user": creds["user"],
            "os_type": host.os_type or "linux",
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes"
        }

        # Handle Private Key
        if creds["auth_type"] == "key" and creds["private_key"]:
            key_content = creds["private_key"].strip() + "\n"
            
            # If private key has a passphrase, decrypt it in-memory for the temporary key file
            if creds.get("passphrase"):
                try:
                    from cryptography.hazmat.primitives import serialization
                    loaded_key = serialization.load_ssh_private_key(
                        key_content.encode("utf-8"),
                        password=creds["passphrase"].encode("utf-8")
                    )
                    key_content = loaded_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode("utf-8")
                except Exception:
                    # Fallback to passing passphrase parameter
                    host_vars["ansible_ssh_passphrase"] = creds["passphrase"]

            key_file = os.path.join(keys_dir, f"key_{host.id}")
            with open(key_file, "w", encoding="utf-8") as kf:
                kf.write(key_content)
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass
            host_vars["ansible_ssh_private_key_file"] = key_file
            if creds.get("passphrase"):
                host_vars["ansible_ssh_passphrase"] = creds["passphrase"]
        elif creds["password"]:
            host_vars["ansible_password"] = creds["password"]
            host_vars["ansible_ssh_common_args"] = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

        # Handle privilege escalation
        if creds["become_method"] in ("sudo", "su") and host.os_type == "linux":
            # If logged in as non-root (e.g. itsgsrv)
            if creds["user"] != "root":
                host_vars["ansible_become"] = True
                host_vars["ansible_become_method"] = creds["become_method"]
                if creds["sudo_password"]:
                    host_vars["ansible_become_password"] = creds["sudo_password"]

        inventory_data["all"]["hosts"][host.name] = host_vars

    inventory_file = os.path.join(temp_dir, "inventory.yml")
    with open(inventory_file, "w", encoding="utf-8") as f:
        yaml.dump(inventory_data, f, default_flow_style=False)

    return inventory_file


def parse_ansible_recap(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse PLAY RECAP line by line to extract status of each host."""
    results = {}
    lines = output.splitlines()
    in_recap = False

    for line in lines:
        if "PLAY RECAP" in line:
            in_recap = True
            continue
        if in_recap and line.strip():
            # Example: srv-db01 : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
            parts = line.split(":")
            if len(parts) >= 2:
                hostname = parts[0].strip()
                stats_str = parts[1].strip()
                stats = {}
                for item in stats_str.split():
                    if "=" in item:
                        k, v = item.split("=", 1)
                        try:
                            stats[k] = int(v)
                        except ValueError:
                            stats[k] = 0

                unreachable = stats.get("unreachable", 0) > 0
                failed = stats.get("failed", 0) > 0
                ok = stats.get("ok", 0) > 0
                changed = stats.get("changed", 0) > 0

                if unreachable:
                    status = "unreachable"
                elif failed:
                    status = "failed"
                elif ok or changed:
                    status = "ok"
                else:
                    status = "unknown"

                results[hostname] = {
                    "status": status,
                    "stats": stats,
                    "summary": stats_str
                }

    return results


def run_ansible_task(app, task_id: int, playbook_name: str, host_ids: List[int], extra_vars: Dict[str, Any]):
    """Execute Ansible Playbook in background thread."""
    with app.app_context():
        from models import db, Host, TaskJob

        task = TaskJob.query.get(task_id)
        if not task:
            return

        task.status = "running"
        db.session.commit()

        hosts = Host.query.filter(Host.id.in_(host_ids)).all()
        if not hosts:
            task.status = "failed"
            task.log_output = "No hosts selected for execution."
            task.finished_at = datetime.utcnow()
            db.session.commit()
            return

        temp_dir = tempfile.mkdtemp(prefix="ansible_run_")
        try:
            inventory_file = generate_inventory(hosts, temp_dir, db.session)
            
            # Write extra vars file
            extra_vars_file = os.path.join(temp_dir, "extra_vars.json")
            with open(extra_vars_file, "w", encoding="utf-8") as evf:
                json.dump(extra_vars, evf, ensure_ascii=False)

            playbook_path = os.path.join(os.path.dirname(__file__), "playbooks", playbook_name)
            forks = int(os.getenv("ANSIBLE_FORKS", "50"))
            timeout = int(os.getenv("ANSIBLE_TIMEOUT", "5"))

            ansible_cmd = shutil.which("ansible-playbook")
            
            if ansible_cmd:
                cmd = [
                    ansible_cmd,
                    "-i", inventory_file,
                    playbook_path,
                    "-e", f"@{extra_vars_file}",
                    "-f", str(forks),
                    "-T", str(timeout)
                ]
                
                # Run Ansible
                env = os.environ.copy()
                env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
                env["ANSIBLE_RETRY_FILES_ENABLED"] = "False"
                env["ANSIBLE_STDOUT_CALLBACK"] = "default"
                
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=300,
                    env=env
                )
                output = proc.stdout
            else:
                # Mock / Dry-run fallback if running on system without native ansible-playbook (e.g. initial dev test)
                output = f"[ANSIBLE-WEB SIMULATION]\nansible-playbook CLI is not in PATH.\nTarget hosts: {len(hosts)}\nPlaybook: {playbook_name}\n"
                output += "\nPLAY RECAP *********************************************************************\n"
                for h in hosts:
                    output += f"{h.name} : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"

            # Parse results
            recap_results = parse_ansible_recap(output)
            
            success_count = 0
            failed_count = 0
            details = {}

            now = datetime.utcnow()
            host_map = {h.name: h for h in hosts}

            for h in hosts:
                res = recap_results.get(h.name, {"status": "unreachable", "summary": "No recap returned"})
                status = res["status"]
                details[h.name] = res

                if status == "ok":
                    success_count += 1
                    if task.task_type == "ping":
                        h.last_status = "online"
                        h.last_checked_at = now
                        h.last_error = None
                else:
                    failed_count += 1
                    if task.task_type == "ping":
                        h.last_status = "offline"
                        h.last_checked_at = now
                        h.last_error = res.get("summary")

            task.success_count = success_count
            task.failed_count = failed_count
            task.details_json = json.dumps(details, ensure_ascii=False)
            task.log_output = output
            task.finished_at = datetime.utcnow()

            if failed_count == 0:
                task.status = "success"
            elif success_count == 0:
                task.status = "failed"
            else:
                task.status = "partial"

            db.session.commit()

        except Exception as e:
            task.status = "failed"
            task.log_output = f"Execution Error: {str(e)}"
            task.finished_at = datetime.utcnow()
            db.session.commit()
        finally:
            # Clean up temporary inventory and private key files
            shutil.rmtree(temp_dir, ignore_errors=True)


def dispatch_task(app, task_type: str, playbook_name: str, host_ids: List[int], extra_vars: Dict[str, Any], user_id: Optional[int], summary: str, filter_info: str = "") -> int:
    """Create TaskJob record and submit to thread pool."""
    from models import db, TaskJob, AuditLog

    task = TaskJob(
        task_type=task_type,
        status="pending",
        summary=summary,
        filter_info=filter_info,
        user_id=user_id,
        target_count=len(host_ids),
        created_at=datetime.utcnow()
    )
    db.session.add(task)
    
    audit = AuditLog(
        user_id=user_id,
        action=task_type.upper(),
        target=f"{len(host_ids)} hosts",
        description=summary
    )
    db.session.add(audit)
    db.session.commit()

    # Dispatch to background thread
    executor.submit(run_ansible_task, app, task.id, playbook_name, host_ids, extra_vars)
    return task.id
