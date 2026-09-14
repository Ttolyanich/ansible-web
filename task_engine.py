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

    target_os = host.os_type if host.os_type in ("linux", "windows") else "linux"

    profile = None
    if host.override_credential:
        profile = host.override_credential
    elif host.group and host.group.credential:
        profile = host.group.credential
    else:
        profile = CredentialProfile.query.filter_by(os_type=target_os, is_default=True).first()
        if not profile:
            profile = CredentialProfile.query.filter_by(os_type=target_os).first()
        if not profile:
            profile = CredentialProfile.query.filter_by(is_default=True).first()
        if not profile:
            profile = CredentialProfile.query.first()

    creds = {
        "user": "root" if target_os == "linux" else "Administrator",
        "port": 22,
        "auth_type": "key",
        "private_key": "",
        "passphrase": "",
        "password": "",
        "sudo_password": "",
        "become_method": "sudo" if target_os == "linux" else "none"
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


def get_candidate_credentials(host, db_session) -> List[Dict[str, Any]]:
    """
    Returns an ordered list of candidate credential dictionaries to try for this host.
    Prioritizes:
    1. Assigned host profile (if set)
    2. Assigned group profile (if set)
    3. Default profile for host's OS
    4. Other profiles matching host's OS
    For each profile, prepares variants (key auth vs password auth) based on profile.auth_type and available secrets.
    """
    from models import CredentialProfile

    target_os = host.os_type if host.os_type in ("linux", "windows") else "linux"
    profiles_to_try = []

    # 1. Primary profile
    primary_profile = None
    if host.override_credential:
        primary_profile = host.override_credential
    elif host.group and host.group.credential:
        primary_profile = host.group.credential
    else:
        primary_profile = CredentialProfile.query.filter_by(os_type=target_os, is_default=True).first()

    if primary_profile:
        profiles_to_try.append(primary_profile)

    # 2. All other profiles matching target_os
    other_profiles = CredentialProfile.query.filter_by(os_type=target_os).order_by(
        CredentialProfile.is_default.desc(), 
        CredentialProfile.id
    ).all()
    for p in other_profiles:
        if primary_profile and p.id == primary_profile.id:
            continue
        profiles_to_try.append(p)

    candidates = []

    def make_cred_dict(prof, auth_mode: str) -> Dict[str, Any]:
        return {
            "profile_id": prof.id if prof else None,
            "profile_name": prof.name if prof else "System Default",
            "user": (prof.ssh_user if prof else None) or ("root" if target_os == "linux" else "Administrator"),
            "port": (prof.ssh_port if prof else None) or 22,
            "auth_type": auth_mode,
            "private_key": prof.private_key if prof else "",
            "passphrase": prof.passphrase if prof else "",
            "password": prof.password if prof else "",
            "sudo_password": prof.sudo_password if prof else "",
            "become_method": (prof.become_method if prof else None) or ("sudo" if target_os == "linux" else "none")
        }

    for prof in profiles_to_try:
        has_key = bool(prof.private_key and prof.private_key.strip())
        has_pwd = bool(prof.password and prof.password.strip())
        pref_auth = prof.auth_type or "key"

        if pref_auth == "password":
            if has_pwd:
                candidates.append(make_cred_dict(prof, "password"))
            if has_key:
                candidates.append(make_cred_dict(prof, "key"))
        else:
            if has_key:
                candidates.append(make_cred_dict(prof, "key"))
            if has_pwd:
                candidates.append(make_cred_dict(prof, "password"))

        if not has_key and not has_pwd:
            candidates.append(make_cred_dict(prof, pref_auth))

    if not candidates:
        candidates.append({
            "profile_id": None,
            "profile_name": "Built-in Default",
            "user": "root" if target_os == "linux" else "Administrator",
            "port": 22,
            "auth_type": "key",
            "private_key": "",
            "passphrase": "",
            "password": "",
            "sudo_password": "",
            "become_method": "sudo" if target_os == "linux" else "none"
        })

    return candidates


def generate_inventory(hosts: list, temp_dir: str, db_session, host_creds_map: Optional[Dict[str, dict]] = None) -> str:
    """Generate YAML inventory file with resolved credentials and SSH options."""
    inventory_data = {
        "all": {
            "hosts": {}
        }
    }

    try:
        os.chmod(temp_dir, 0o700)
    except Exception:
        pass

    keys_dir = os.path.join(temp_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    try:
        os.chmod(keys_dir, 0o700)
    except Exception:
        pass

    for host in hosts:
        if host_creds_map and host.name in host_creds_map:
            creds = host_creds_map[host.name]
        else:
            creds = resolve_credentials(host, db_session)

        target_os = host.os_type if host.os_type in ("linux", "windows") else "linux"

        host_vars = {
            "ansible_host": host.ip_address,
            "ansible_port": creds["port"],
            "ansible_user": creds["user"],
            "os_type": target_os,
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
        }

        # Handle Private Key vs Password
        if creds.get("auth_type") == "key" and creds.get("private_key"):
            key_content = creds["private_key"].strip() + "\n"
            
            # If private key has a passphrase, decrypt it in-memory for the temporary key file
            if creds.get("passphrase"):
                try:
                    from cryptography.hazmat.primitives import serialization
                    pass_bytes = creds["passphrase"].encode("utf-8")
                    key_bytes = key_content.encode("utf-8")
                    loaded_key = None

                    try:
                        loaded_key = serialization.load_ssh_private_key(key_bytes, password=pass_bytes)
                    except Exception:
                        pass

                    if not loaded_key:
                        try:
                            loaded_key = serialization.load_pem_private_key(key_bytes, password=pass_bytes)
                        except Exception:
                            pass

                    if loaded_key:
                        for fmt in [
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.PrivateFormat.OpenSSH,
                            serialization.PrivateFormat.PKCS8
                        ]:
                            try:
                                key_content = loaded_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=fmt,
                                    encryption_algorithm=serialization.NoEncryption()
                                ).decode("utf-8")
                                break
                            except Exception:
                                continue
                except Exception as ex:
                    logger.warning(f"Failed to decrypt private key for {host.name}: {ex}")
                    if creds.get("passphrase"):
                        host_vars["ansible_ssh_passphrase"] = creds["passphrase"]

            key_file = os.path.join(keys_dir, f"key_{host.id}_{abs(hash(creds['user'])) % 10000}")
            with open(key_file, "w", encoding="utf-8") as kf:
                kf.write(key_content)
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass

            host_vars["ansible_ssh_private_key_file"] = key_file
            host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes -o IdentitiesOnly=yes -o PubkeyAcceptedKeyTypes=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa"
            if creds.get("passphrase"):
                host_vars["ansible_ssh_passphrase"] = creds["passphrase"]

        elif creds.get("auth_type") == "password" and creds.get("password"):
            host_vars["ansible_password"] = creds["password"]
            # No BatchMode=yes so sshpass can pass the password

        elif creds.get("private_key"):
            key_file = os.path.join(keys_dir, f"key_{host.id}")
            with open(key_file, "w", encoding="utf-8") as kf:
                kf.write(creds["private_key"].strip() + "\n")
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass
            host_vars["ansible_ssh_private_key_file"] = key_file
            host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes -o IdentitiesOnly=yes"

        elif creds.get("password"):
            host_vars["ansible_password"] = creds["password"]

        elif os.path.exists("/root/.ssh/id_rsa"):
            host_vars["ansible_ssh_private_key_file"] = "/root/.ssh/id_rsa"
            host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes"
        elif os.path.exists("/root/.ssh/id_ed25519"):
            host_vars["ansible_ssh_private_key_file"] = "/root/.ssh/id_ed25519"
            host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes"

        # Handle privilege escalation
        if creds["become_method"] in ("sudo", "su") and host.os_type == "linux":
            if creds["user"] != "root":
                host_vars["ansible_become"] = True
                host_vars["ansible_become_method"] = creds["become_method"]
                if creds.get("sudo_password"):
                    host_vars["ansible_become_password"] = creds["sudo_password"]

        inventory_data["all"]["hosts"][host.name] = host_vars

    inventory_file = os.path.join(temp_dir, "inventory.yml")
    with open(inventory_file, "w", encoding="utf-8") as f:
        yaml.dump(inventory_data, f, default_flow_style=False)

    return inventory_file


def extract_host_errors(output: str) -> Dict[str, str]:
    """Extract human-readable error reason per host from Ansible log output."""
    errors = {}
    lines = output.splitlines()
    for line in lines:
        line_clean = line.strip()
        if line_clean.startswith("fatal: [") or line_clean.startswith("failed: ["):
            try:
                start_bracket = line_clean.find("[") + 1
                end_bracket = line_clean.find("]")
                hostname = line_clean[start_bracket:end_bracket].strip()
                rest = line_clean[end_bracket+1:]

                if "Permission denied" in rest:
                    err_text = "Permission denied (проверьте SSH-ключ / пароль)"
                elif "timed out" in rest.lower() or "timeout" in rest.lower():
                    err_text = "Connection timed out (хост не отвечает по SSH)"
                elif "Connection refused" in rest:
                    err_text = "Connection refused (порт SSH закрыт)"
                elif "No route to host" in rest:
                    err_text = "No route to host (сеть недоступна)"
                elif "Host key verification failed" in rest:
                    err_text = "Host key verification failed"
                elif '"msg":' in rest:
                    try:
                        idx_json = rest.find("{")
                        if idx_json != -1:
                            data = json.loads(rest[idx_json:])
                            raw_msg = data.get("msg", "")
                            err_text = raw_msg.splitlines()[-1] if raw_msg else rest[:120]
                    except Exception:
                        err_text = rest[:120]
                else:
                    err_text = rest[:120]

                errors[hostname] = err_text
            except Exception:
                pass
    return errors


def parse_ansible_recap(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse PLAY RECAP line by line to extract status of each host."""
    results = {}
    lines = output.splitlines()
    in_recap = False
    host_errors = extract_host_errors(output)

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
                ignored = stats.get("ignored", 0) > 0
                ok = stats.get("ok", 0) > 0
                changed = stats.get("changed", 0) > 0

                # If unreachable, failed, or ignored errors occurred, host is NOT ok!
                if unreachable:
                    status = "unreachable"
                elif failed or ignored:
                    status = "failed"
                elif (ok or changed) and not ignored:
                    status = "ok"
                else:
                    status = "unknown"

                err_msg = host_errors.get(hostname) or stats_str

                results[hostname] = {
                    "status": status,
                    "stats": stats,
                    "summary": stats_str,
                    "error": err_msg if status != "ok" else None
                }

    return results


def run_ansible_task(app, task_id: int, playbook_name: str, host_ids: List[int], extra_vars: Dict[str, Any]):
    """Execute Ansible Playbook in background thread with smart multi-credential fallback and auto-learning."""
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

        # Precompute candidate credential sequences for each host
        host_candidates = {h.name: get_candidate_credentials(h, db.session) for h in hosts}
        pending_hosts = {h.name: h for h in hosts}
        host_attempt_indices = {h.name: 0 for h in hosts}
        final_results = {}
        aggregated_logs = []

        pass_num = 1
        max_passes = 6
        forks = int(os.getenv("ANSIBLE_FORKS", "50"))
        timeout = int(os.getenv("ANSIBLE_TIMEOUT", "5"))
        ansible_cmd = shutil.which("ansible-playbook")
        playbook_path = os.path.join(os.path.dirname(__file__), "playbooks", playbook_name)

        while pending_hosts and pass_num <= max_passes:
            current_batch = []
            current_creds_map = {}

            for h_name, h in list(pending_hosts.items()):
                idx = host_attempt_indices[h_name]
                cands = host_candidates[h_name]
                if idx < len(cands):
                    current_batch.append(h)
                    current_creds_map[h_name] = cands[idx]
                else:
                    # No more candidates to try for this host
                    del pending_hosts[h_name]

            if not current_batch:
                break

            if pass_num == 1:
                pass_title = f"=== [ПРОХОД {pass_num}] Запуск Ansible для {len(current_batch)} хостов с основными профилями ==="
            else:
                pass_title = f"=== [ПРОХОД {pass_num} (АВТО-ПОДБОР)] Повторная попытка для {len(current_batch)} хостов с альтернативными профилями ==="

            aggregated_logs.append(f"\n{pass_title}\n")

            batch_temp_dir = tempfile.mkdtemp(prefix=f"ansible_pass_{pass_num}_")
            try:
                inventory_file = generate_inventory(current_batch, batch_temp_dir, db.session, current_creds_map)
                extra_vars_file = os.path.join(batch_temp_dir, "extra_vars.json")
                with open(extra_vars_file, "w", encoding="utf-8") as evf:
                    json.dump(extra_vars, evf, ensure_ascii=False)

                if ansible_cmd:
                    cmd = [
                        ansible_cmd,
                        "-i", inventory_file,
                        playbook_path,
                        "-e", f"@{extra_vars_file}",
                        "-f", str(forks),
                        "-T", str(timeout)
                    ]
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
                    pass_output = proc.stdout
                else:
                    # Simulation mode fallback
                    pass_output = f"[ANSIBLE-WEB SIMULATION - PASS {pass_num}]\nTarget hosts: {len(current_batch)}\n"
                    pass_output += "PLAY RECAP *********************************************************************\n"
                    for h in current_batch:
                        pass_output += f"{h.name} : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"

                aggregated_logs.append(pass_output)
                recap_results = parse_ansible_recap(pass_output)

                # Process results of this pass
                for h in current_batch:
                    res = recap_results.get(h.name, {"status": "unreachable", "summary": "No recap returned"})
                    used_cred = current_creds_map[h.name]

                    if res["status"] == "ok":
                        # SUCCESS!
                        res["matched_profile"] = used_cred["profile_name"]
                        res["matched_user"] = used_cred["user"]
                        res["matched_auth"] = used_cred["auth_type"]
                        final_results[h.name] = res

                        # Auto-learn: If this profile succeeded, save it directly to host so future tasks need no retry
                        if used_cred["profile_id"] and h.credential_id != used_cred["profile_id"]:
                            h.credential_id = used_cred["profile_id"]
                            try:
                                db.session.commit()
                                aggregated_logs.append(
                                    f"[АВТО-ПРИВЯЗКА] Хост '{h.name}' успешно авторизован под '{used_cred['profile_name']}' ({used_cred['user']}). Профиль сохранён в базу для этого хоста.\n"
                                )
                            except Exception:
                                db.session.rollback()

                        if h.name in pending_hosts:
                            del pending_hosts[h.name]
                    else:
                        # Host failed this pass
                        err_text = (res.get("error") or res.get("summary") or "").lower()
                        is_auth_error = any(kw in err_text for kw in [
                            "permission denied", "authentication failed", "error in libcrypto",
                            "auth fail", "password", "publickey"
                        ])

                        cands = host_candidates[h.name]
                        next_idx = host_attempt_indices[h.name] + 1

                        if is_auth_error and next_idx < len(cands):
                            # Move to next candidate in next pass!
                            host_attempt_indices[h.name] = next_idx
                            next_cand = cands[next_idx]
                            aggregated_logs.append(
                                f"[ПОДБОР] Хост '{h.name}': отказ авторизации под '{used_cred['profile_name']}' ({used_cred['user']}, {used_cred['auth_type']}). Следующая попытка: '{next_cand['profile_name']}' ({next_cand['user']}, {next_cand['auth_type']})...\n"
                            )
                        else:
                            # Unreachable / network timeout OR all candidate profiles exhausted
                            final_results[h.name] = res
                            if h.name in pending_hosts:
                                del pending_hosts[h.name]

            except Exception as e:
                aggregated_logs.append(f"[ОШИБКА ВЫПОЛНЕНИЯ ПРОХОДА {pass_num}]: {str(e)}\n")
                break
            finally:
                shutil.rmtree(batch_temp_dir, ignore_errors=True)

            pass_num += 1

        # Finalize task metrics and update host states
        now = datetime.utcnow()
        success_count = 0
        failed_count = 0

        for h in hosts:
            res = final_results.get(h.name, {"status": "unreachable", "summary": "No recap returned"})
            if res["status"] == "ok":
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
                    h.last_error = res.get("error") or res.get("summary")

        task.success_count = success_count
        task.failed_count = failed_count
        task.details_json = json.dumps(final_results, ensure_ascii=False)
        task.log_output = "".join(aggregated_logs)
        task.finished_at = now

        if failed_count == 0:
            task.status = "success"
        elif success_count == 0:
            task.status = "failed"
        else:
            task.status = "partial"

        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to commit final task state: {e}")


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
