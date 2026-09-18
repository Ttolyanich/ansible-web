import os
import sys
import json
import yaml
import shutil
import tempfile
import subprocess
import logging
import ctypes
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Background executor for tasks
executor = ThreadPoolExecutor(max_workers=4)
active_task_processes: Dict[int, subprocess.Popen] = {}


def cancel_task(task_id: int) -> bool:
    """Terminates running subprocess for a given task ID."""
    proc = active_task_processes.get(task_id)
    if proc:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
            return True
        except Exception as e:
            logger.warning(f"Error canceling task {task_id}: {e}")
            return False
    return False



def enable_openssl_legacy_provider():
    """
    OpenSSL 3.0 (Debian 12/Ubuntu 22+) disables legacy algorithms like DES-EDE3-CBC by default.
    Many older RSA keys use DES-EDE3-CBC encryption, which causes 'error in libcrypto'
    in OpenSSH and 'unsupported algorithm' in cryptography.
    This enables the legacy provider dynamically.
    """
    cfg_path = os.path.join(os.path.dirname(__file__), "openssl_legacy.cnf")
    if not os.path.exists(cfg_path):
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(
                    "openssl_conf = openssl_init\n\n"
                    "[openssl_init]\n"
                    "providers = provider_sect\n\n"
                    "[provider_sect]\n"
                    "default = default_sect\n"
                    "legacy = legacy_sect\n\n"
                    "[default_sect]\n"
                    "activate = 1\n\n"
                    "[legacy_sect]\n"
                    "activate = 1\n"
                )
        except Exception:
            pass
    if os.path.exists(cfg_path):
        os.environ["OPENSSL_CONF"] = cfg_path

    # Also load legacy provider via libcrypto if accessible in current process
    for lib_name in [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib/aarch64-linux-gnu/libcrypto.so.3",
        "libcrypto.so.3",
        "libcrypto.so"
    ]:
        try:
            lib = ctypes.CDLL(lib_name)
            if hasattr(lib, "OSSL_PROVIDER_load"):
                lib.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
                lib.OSSL_PROVIDER_load.restype = ctypes.c_void_p
                lib.OSSL_PROVIDER_load(None, b"legacy")
                lib.OSSL_PROVIDER_load(None, b"default")
                break
        except Exception:
            continue


# Enable on module import
enable_openssl_legacy_provider()


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

    if getattr(host, "ssh_port", None):
        creds["port"] = host.ssh_port

    return creds


def get_candidate_credentials(host, db_session, explicit_profile_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Returns an ordered list of candidate credential dictionaries to try for this host.
    Prioritizes:
    0. Explicit profile passed for this task run (if specified)
    1. Assigned host profile (if set)
    2. Assigned group profile (if set)
    3. Default profile for host's OS
    4. Other profiles matching host's OS
    For each profile, prepares variants (key auth vs password auth) based on profile.auth_type and available secrets.
    """
    from models import CredentialProfile

    target_os = host.os_type if host.os_type in ("linux", "windows") else "linux"
    profiles_to_try = []

    # 0. Explicit profile passed for this specific task
    explicit_profile = None
    if explicit_profile_id:
        explicit_profile = db_session.get(CredentialProfile, explicit_profile_id)
        if explicit_profile:
            profiles_to_try.append(explicit_profile)

    # 1. Primary profile
    primary_profile = None
    if host.override_credential:
        primary_profile = host.override_credential
    elif host.group and host.group.credential:
        primary_profile = host.group.credential
    else:
        primary_profile = CredentialProfile.query.filter_by(os_type=target_os, is_default=True).first()

    if primary_profile and (not explicit_profile or primary_profile.id != explicit_profile.id):
        profiles_to_try.append(primary_profile)

    # 2. All other profiles matching target_os
    other_profiles = CredentialProfile.query.filter_by(os_type=target_os).order_by(
        CredentialProfile.is_default.desc(), 
        CredentialProfile.id
    ).all()
    for p in other_profiles:
        if explicit_profile and p.id == explicit_profile.id:
            continue
        if primary_profile and p.id == primary_profile.id:
            continue
        profiles_to_try.append(p)

    candidates = []

    custom_port = getattr(host, "ssh_port", None)

    def make_cred_dict(prof, auth_mode: str, eff_pwd: str = "") -> Dict[str, Any]:
        pwd = eff_pwd or (prof.password if prof else "") or (prof.passphrase if prof and not prof.password else "")
        return {
            "profile_id": prof.id if prof else None,
            "profile_name": prof.name if prof else "System Default",
            "user": (prof.ssh_user if prof else None) or ("root" if target_os == "linux" else "Administrator"),
            "port": custom_port or (prof.ssh_port if prof else None) or 22,
            "auth_type": auth_mode,
            "private_key": prof.private_key if prof else "",
            "passphrase": prof.passphrase if prof else "",
            "password": pwd,
            "sudo_password": prof.sudo_password if prof else "",
            "become_method": (prof.become_method if prof else None) or ("sudo" if target_os == "linux" else "none")
        }

    for prof in profiles_to_try:
        raw_key = (prof.private_key or "").strip() if prof else ""
        raw_pass = (prof.password or "").strip() if prof else ""
        raw_passphrase = (prof.passphrase or "").strip() if prof else ""

        # Validate key format
        key_valid = False
        if raw_key:
            key_valid, _ = validate_ssh_key(raw_key, raw_passphrase)

        has_key = bool(raw_key and key_valid)

        # If user entered server password into either password or passphrase field:
        effective_pwd = raw_pass or raw_passphrase
        has_pwd = bool(effective_pwd)

        pref_auth = prof.auth_type or ("key" if has_key else "password")

        # If key is broken/invalid but password/passphrase exists, prefer password!
        if not has_key and raw_key and has_pwd:
            pref_auth = "password"

        if pref_auth == "password":
            if has_pwd:
                candidates.append(make_cred_dict(prof, "password", effective_pwd))
            if has_key:
                candidates.append(make_cred_dict(prof, "key", effective_pwd))
        else:
            if has_key:
                candidates.append(make_cred_dict(prof, "key", effective_pwd))
            if has_pwd:
                candidates.append(make_cred_dict(prof, "password", effective_pwd))

        if not has_key and not has_pwd:
            candidates.append(make_cred_dict(prof, pref_auth, ""))

    if not candidates:
        candidates.append({
            "profile_id": None,
            "profile_name": "Built-in Default",
            "user": "root" if target_os == "linux" else "Administrator",
            "port": custom_port or 22,
            "auth_type": "key",
            "private_key": "",
            "passphrase": "",
            "password": "",
            "sudo_password": "",
            "become_method": "sudo" if target_os == "linux" else "none"
        })

    return candidates


def normalize_private_key(raw_key: Optional[str]) -> str:
    """
    Cleans up private key formatting:
    - Normalizes CRLF and CR to standard Unix LF (\n)
    - Removes trailing spaces on each line
    - Preserves necessary blank lines (e.g. between PEM headers like DEK-Info/Proc-Type and payload)
    - Ensures exactly one newline at the end
    """
    if not raw_key:
        return ""
    normalized = raw_key.replace("\r\n", "\n").replace("\r", "\n").strip()
    lines = normalized.split("\n")
    clean_lines = []
    prev_blank = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if not prev_blank:
                clean_lines.append("")
                prev_blank = True
        else:
            clean_lines.append(stripped)
            prev_blank = False

    result = "\n".join(clean_lines).strip()

    # In PEM encrypted keys (RFC 1421), an empty line is mandatory after headers (DEK-Info / Proc-Type)
    if "DEK-Info:" in result and "\n\n" not in result:
        parts = result.split("\n")
        fixed_parts = []
        for p in parts:
            fixed_parts.append(p)
            if p.startswith("DEK-Info:"):
                fixed_parts.append("")
        result = "\n".join(fixed_parts)

    return result + "\n"


_key_validation_cache: Dict[Tuple[str, str], Tuple[bool, str]] = {}

def validate_ssh_key(raw_key: str, passphrase: str = "") -> Tuple[bool, str]:
    """
    Validates private key format and checks if passphrase is required / correct.
    Supports OpenSSH, PEM, PKCS#8, and legacy ciphers (DES-EDE3-CBC).
    """
    if not raw_key or not raw_key.strip():
        return True, ""

    clean = raw_key.strip()
    eff_pass = (passphrase or "")

    # 1. Check for public key mistakenly pasted
    if clean.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2", "ssh-dss")):
        return False, "Вы вставили открытый (публичный) ключ вместо закрытого (приватного)! Приватный ключ начинается со строки '-----BEGIN ... PRIVATE KEY-----'."

    # 2. Check for PuTTY PPK format
    if clean.startswith("PuTTY-User-Key-File"):
        return False, "Вы вставили ключ в формате PuTTY (.ppk). OpenSSH не поддерживает формат PPK напрямую. Откройте ключ в программе PuTTYgen и экспортируйте его через меню: Conversions -> Export OpenSSH key."

    # 3. Check for standard BEGIN header
    if not clean.startswith("-----BEGIN"):
        return False, "Неверный формат ключа: приватный SSH-ключ должен начинаться со строки '-----BEGIN ... PRIVATE KEY-----'."

    cache_key = (clean, eff_pass.strip())
    if cache_key in _key_validation_cache:
        return _key_validation_cache[cache_key]

    enable_openssl_legacy_provider()

    # 4. Check loading & passphrase with cryptography
    key_bytes = normalize_private_key(clean).encode("utf-8")
    loaded = False

    for test_pass in ([eff_pass.strip().encode("utf-8"), eff_pass.encode("utf-8")] if eff_pass else [None]):
        try:
            from cryptography.hazmat.primitives import serialization
            try:
                k = serialization.load_ssh_private_key(key_bytes, password=test_pass)
                if k:
                    loaded = True
                    break
            except Exception:
                pass

            if not loaded:
                try:
                    k = serialization.load_pem_private_key(key_bytes, password=test_pass)
                    if k:
                        loaded = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

    # Fallback 1: Native ssh-keygen verification (handles OpenSSH bcrypt KDF, AES-CTR, etc.)
    if not loaded:
        ssh_keygen = shutil.which("ssh-keygen")
        if ssh_keygen:
            tf_path = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tf:
                    tf.write(normalize_private_key(clean))
                    tf_path = tf.name
                try:
                    os.chmod(tf_path, 0o600)
                except Exception:
                    pass
                for tp in ([eff_pass.strip(), eff_pass] if eff_pass else [""]):
                    res = subprocess.run(
                        [ssh_keygen, "-y", "-P", tp, "-f", tf_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if res.returncode == 0 and res.stdout:
                        loaded = True
                        break
            except Exception as ex:
                logger.debug(f"ssh-keygen validate fallback error: {ex}")
            finally:
                if tf_path and os.path.exists(tf_path):
                    try:
                        os.remove(tf_path)
                    except Exception:
                        pass

    # Fallback 2: OpenSSL CLI with legacy provider (DES-EDE3-CBC, PKCS8)
    if not loaded and eff_pass:
        openssl_bin = shutil.which("openssl")
        if openssl_bin:
            env_sub = os.environ.copy()
            cfg_path = os.path.join(os.path.dirname(__file__), "openssl_legacy.cnf")
            if os.path.exists(cfg_path):
                env_sub["OPENSSL_CONF"] = cfg_path
            for subcmd in ["pkey", "rsa"]:
                for tp in [eff_pass.strip(), eff_pass]:
                    try:
                        res = subprocess.run(
                            [openssl_bin, subcmd, "-passin", f"pass:{tp}"],
                            input=key_bytes,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env_sub,
                            timeout=5
                        )
                        if res.returncode == 0 and b"PRIVATE KEY" in res.stdout:
                            loaded = True
                            break
                    except Exception as ex:
                        logger.debug(f"openssl {subcmd} validate fallback: {ex}")
                if loaded:
                    break

    if not loaded:
        is_encrypted = ("ENCRYPTED" in clean or "Proc-Type: 4,ENCRYPTED" in clean)
        if is_encrypted and not eff_pass:
            return (False, "Приватный ключ защищён парольной фразой! Пожалуйста, укажите 'Парольную фразу ключа' в поле профиля.")

        if eff_pass:
            return (False, "Не удалось расшифровать приватный ключ. Проверьте правильность введённой парольной фразы.")

        # If not explicitly marked as ENCRYPTED and no pass, accept it as raw key
        res = (True, "")
        _key_validation_cache[cache_key] = res
        return res

    res = (True, "")
    _key_validation_cache[cache_key] = res
    return res


def write_clean_key_file(key_text: str, passphrase: str, target_file: str) -> bool:
    """
    Writes private key ensuring:
    1. Perfect Unix LF line endings (no \r or CRLF that causes 'error in libcrypto')
    2. Attempts to decrypt in-place so Ansible can use passwordless key directly
    3. Writes with strict 0600 permissions
    """
    clean_key = normalize_private_key(key_text)
    if not clean_key:
        return False

    final_content = clean_key
    enable_openssl_legacy_provider()

    # Attempt to load and re-serialize through cryptography if possible
    loaded_key = None
    try:
        from cryptography.hazmat.primitives import serialization
        key_bytes = clean_key.encode("utf-8")
        pass_bytes = passphrase.encode("utf-8") if passphrase else None

        for test_pass in ([pass_bytes, passphrase.strip().encode("utf-8")] if pass_bytes else [None]):
            try:
                loaded_key = serialization.load_ssh_private_key(key_bytes, password=test_pass)
                if loaded_key:
                    break
            except Exception:
                pass
            if not loaded_key:
                try:
                    loaded_key = serialization.load_pem_private_key(key_bytes, password=test_pass)
                    if loaded_key:
                        break
                except Exception:
                    pass

        if loaded_key and hasattr(loaded_key, "private_bytes"):
            for enc_fmt in [
                serialization.PrivateFormat.OpenSSH,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.PrivateFormat.PKCS8
            ]:
                try:
                    exported = loaded_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=enc_fmt,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode("utf-8")
                    final_content = normalize_private_key(exported)
                    break
                except Exception:
                    continue
    except Exception as ex:
        logger.debug(f"Cryptography key export note: {ex}")

    # Fallback decryption via openssl CLI if cryptography could not deserialize
    if not loaded_key and passphrase:
        openssl_bin = shutil.which("openssl")
        if openssl_bin:
            env_sub = os.environ.copy()
            cfg_path = os.path.join(os.path.dirname(__file__), "openssl_legacy.cnf")
            if os.path.exists(cfg_path):
                env_sub["OPENSSL_CONF"] = cfg_path
            for subcmd in ["pkey", "rsa"]:
                for tp in [passphrase, passphrase.strip()]:
                    try:
                        res = subprocess.run(
                            [openssl_bin, subcmd, "-passin", f"pass:{tp}"],
                            input=clean_key.encode("utf-8"),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env_sub,
                            timeout=5
                        )
                        if res.returncode == 0 and b"PRIVATE KEY" in res.stdout:
                            final_content = normalize_private_key(res.stdout.decode("utf-8"))
                            loaded_key = True
                            break
                    except Exception as ex:
                        logger.debug(f"openssl {subcmd} write fallback: {ex}")
                if loaded_key:
                    break

    # Write as pure Unix bytes (\n only) in binary mode
    with open(target_file, "wb") as f:
        f.write(final_content.encode("utf-8"))

    try:
        os.chmod(target_file, 0o600)
    except Exception:
        pass

    # If key still has a passphrase, decrypt it in-place using ssh-keygen so Ansible runs passwordless
    if passphrase and not loaded_key:
        ssh_keygen = shutil.which("ssh-keygen")
        if ssh_keygen:
            for tp in [passphrase, passphrase.strip()]:
                try:
                    res = subprocess.run(
                        [ssh_keygen, "-p", "-P", tp, "-N", "", "-f", target_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if res.returncode == 0:
                        logger.info(f"Decrypted private key in-place for Ansible at {target_file}")
                        break
                except Exception as ex:
                    logger.debug(f"ssh-keygen in-place decrypt note: {ex}")

    return True



def generate_inventory(hosts: list, temp_dir: str, db_session, host_creds_map: Optional[Dict[str, dict]] = None, is_ping: bool = False) -> str:
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
        elif host_creds_map and host.id in host_creds_map:
            creds = host_creds_map[host.id]
        elif host_creds_map and str(host.id) in host_creds_map:
            creds = host_creds_map[str(host.id)]
        else:
            creds = resolve_credentials(host, db_session)

        target_os = host.os_type if host.os_type in ("linux", "windows") else "linux"
        effective_port = getattr(host, "ssh_port", None) or creds.get("port") or 22

        host_vars = {
            "ansible_host": host.ip_address,
            "ansible_port": effective_port,
            "ansible_user": creds["user"],
            "os_type": target_os,
            "ansible_ssh_common_args": "-o ControlMaster=no -o ControlPersist=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ConnectionAttempts=2 -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o GSSAPIAuthentication=no -o TCPKeepAlive=yes"
        }

        if target_os == "windows":
            host_vars["ansible_shell_type"] = "cmd"

        # Handle Private Key vs Password
        use_key = False
        if creds.get("auth_type") == "key" and creds.get("private_key"):
            prof_id = creds.get("profile_id")
            if prof_id:
                key_file = os.path.join(keys_dir, f"key_prof_{prof_id}")
            else:
                key_file = os.path.join(keys_dir, f"key_custom_{abs(hash(creds.get('private_key', ''))) % 100000}")

            if not os.path.exists(key_file):
                write_clean_key_file(creds.get("private_key", ""), creds.get("passphrase", ""), key_file)

            if os.path.exists(key_file):
                host_vars["ansible_ssh_private_key_file"] = key_file
                host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes -o IdentitiesOnly=yes -o PubkeyAcceptedKeyTypes=+ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519 -o PubkeyAcceptedAlgorithms=+ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519 -o HostKeyAlgorithms=+ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519"
                if creds.get("passphrase"):
                    host_vars["ansible_ssh_passphrase"] = creds["passphrase"]
                use_key = True

        if not use_key:
            if creds.get("password"):
                host_vars["ansible_password"] = creds["password"]
            elif creds.get("private_key"):
                prof_id = creds.get("profile_id")
                if prof_id:
                    key_file = os.path.join(keys_dir, f"key_prof_{prof_id}")
                else:
                    key_file = os.path.join(keys_dir, f"key_custom_{abs(hash(creds.get('private_key', ''))) % 100000}")

                if not os.path.exists(key_file):
                    write_clean_key_file(creds.get("private_key", ""), creds.get("passphrase", ""), key_file)

                if os.path.exists(key_file):
                    host_vars["ansible_ssh_private_key_file"] = key_file
                    host_vars["ansible_ssh_common_args"] += " -o BatchMode=yes -o IdentitiesOnly=yes"

        # Handle privilege escalation: NEVER escalate on ping checks!
        if not is_ping and creds.get("become_method") in ("sudo", "su") and host.os_type == "linux":
            if creds.get("user") != "root":
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
                elif "task timeout" in rest.lower():
                    err_text = "Task timeout (хост завис при выполнении команды)"
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

        hosts = Host.query.filter(Host.id.in_(host_ids)).all()
        task.status = "running"
        task.log_output = f"[СИСТЕМА] Подготовка задачи для {len(hosts)} серверов...\n"
        try:
            db.session.commit()
        except Exception:
            pass

        if not hosts:
            task.status = "failed"
            task.log_output = "No hosts selected for execution."
            task.finished_at = datetime.utcnow()
            db.session.commit()
            return

        # Determine if an explicit credential profile was specified for this task run
        explicit_cred_id = extra_vars.get("_credential_profile_id")
        if not explicit_cred_id and task.filter_info:
            try:
                meta = json.loads(task.filter_info)
                explicit_cred_id = meta.get("extra_vars", {}).get("_credential_profile_id") or meta.get("credential_profile_id")
            except Exception:
                pass

        try:
            explicit_cred_id = int(explicit_cred_id) if explicit_cred_id else None
        except Exception:
            explicit_cred_id = None

        if explicit_cred_id:
            from models import CredentialProfile
            exp_p = db.session.get(CredentialProfile, explicit_cred_id)
            if exp_p:
                task.log_output += f"[ПРОФИЛЬ] Назначен приоритетный профиль подключения: «{exp_p.name}» (пользователь: {exp_p.ssh_user})\n"

        # Precompute candidate credential sequences for each host
        host_candidates = {h.name: get_candidate_credentials(h, db.session, explicit_profile_id=explicit_cred_id) for h in hosts}
        pending_hosts = {h.name: h for h in hosts}
        host_attempt_indices = {h.name: 0 for h in hosts}
        final_results = {}
        aggregated_logs = [task.log_output] if task.log_output else []

        # Collect secrets that should never appear in log outputs
        secret_mask_set = set()
        if extra_vars:
            tp = extra_vars.get("target_password")
            if tp and str(tp).strip():
                secret_mask_set.add(str(tp).strip())
            for u in extra_vars.get("target_users", []):
                if isinstance(u, dict) and u.get("password") and str(u["password"]).strip():
                    secret_mask_set.add(str(u["password"]).strip())
        for cands in host_candidates.values():
            for c in cands:
                if c.get("password") and str(c["password"]).strip():
                    secret_mask_set.add(str(c["password"]).strip())
                if c.get("passphrase") and str(c["passphrase"]).strip():
                    secret_mask_set.add(str(c["passphrase"]).strip())

        secret_mask_set = {s for s in secret_mask_set if len(s) >= 3}

        def sanitize_log_text(text: str) -> str:
            if not text or not secret_mask_set:
                return text
            for sec in secret_mask_set:
                text = text.replace(sec, "********")
            return text

        pass_num = 1
        max_passes = int(os.getenv("MAX_AUTH_PASSES", "2"))
        forks = int(os.getenv("ANSIBLE_FORKS", "100"))
        ssh_timeout = int(os.getenv("ANSIBLE_TIMEOUT", "15"))
        playbook_timeout = int(os.getenv("ANSIBLE_TASK_TIMEOUT", "900"))
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
                is_ping = (playbook_name == "ping_check.yml")
                inventory_file = generate_inventory(current_batch, batch_temp_dir, db.session, current_creds_map, is_ping=is_ping)
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
                        "-T", str(ssh_timeout)
                    ]
                    env = os.environ.copy()
                    cfg_path = os.path.join(os.path.dirname(__file__), "ansible.cfg")
                    if os.path.exists(cfg_path):
                        env["ANSIBLE_CONFIG"] = cfg_path
                    openssl_cfg = os.path.join(os.path.dirname(__file__), "openssl_legacy.cnf")
                    if os.path.exists(openssl_cfg):
                        env["OPENSSL_CONF"] = openssl_cfg
                    env["PYTHONUNBUFFERED"] = "1"
                    env["ANSIBLE_FORCE_COLOR"] = "0"
                    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
                    env["ANSIBLE_RETRY_FILES_ENABLED"] = "False"
                    env["ANSIBLE_STDOUT_CALLBACK"] = "default"
                    env["ANSIBLE_SSH_RETRIES"] = "1"
                    env["ANSIBLE_TIMEOUT"] = str(ssh_timeout)
                    env["ANSIBLE_TASK_TIMEOUT"] = "30"

                    task.log_output = "".join(aggregated_logs)
                    try:
                        db.session.commit()
                    except Exception:
                        pass

                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        env=env
                    )
                    active_task_processes[task_id] = proc

                    pass_chunks = []
                    last_flush = time.time()

                    try:
                        while True:
                            line = proc.stdout.readline()
                            if not line and proc.poll() is not None:
                                break
                            if line:
                                line = sanitize_log_text(line)
                                pass_chunks.append(line)

                            now = time.time()
                            if (now - last_flush) >= 0.8:
                                # Periodic check for task cancellation and DB flush
                                try:
                                    db.session.refresh(task)
                                    if task.status == "canceled":
                                        proc.terminate()
                                        break
                                except Exception:
                                    pass

                                if pass_chunks:
                                    task.log_output = "".join(aggregated_logs) + "".join(pass_chunks)
                                    try:
                                        db.session.commit()
                                        last_flush = now
                                    except Exception:
                                        db.session.rollback()

                        proc.stdout.close()
                        proc.wait(timeout=5)
                    except Exception as ex:
                        logger.warning(f"Process stream exception: {ex}")
                    finally:
                        active_task_processes.pop(task_id, None)

                    pass_output = "".join(pass_chunks)
                else:
                    # Simulation mode fallback
                    pass_output = f"[ANSIBLE-WEB SIMULATION - PASS {pass_num}]\nTarget hosts: {len(current_batch)}\n"
                    pass_output += "PLAY RECAP *********************************************************************\n"
                    for h in current_batch:
                        pass_output += f"{h.name} : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"

                aggregated_logs.append(pass_output)
                task.log_output = "".join(aggregated_logs)
                try:
                    db.session.commit()
                except Exception:
                    pass
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
                        # Only stop trying if host is definitely dead (no route or closed port)
                        is_dead_host = any(kw in err_text for kw in [
                            "no route to host", "connection refused", "name or service not known"
                        ])

                        cands = host_candidates[h.name]
                        next_idx = host_attempt_indices[h.name] + 1

                        if not is_dead_host and next_idx < len(cands):
                            # Move to next candidate in next pass!
                            host_attempt_indices[h.name] = next_idx
                            next_cand = cands[next_idx]
                            aggregated_logs.append(
                                f"[ПОДБОР] Хост '{h.name}': отказ авторизации под '{used_cred['profile_name']}' ({used_cred['user']}, {used_cred['auth_type']}). Следующая попытка: '{next_cand['profile_name']}' ({next_cand['user']}, {next_cand['auth_type']})...\n"
                            )
                        else:
                            # Dead host OR all candidate profiles exhausted
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


def get_service_accounts_exclusions() -> List[str]:
    """
    Loads service account exclusions dynamically without storing confidential company accounts in Git:
    1. From local file instance/service_accounts.txt (ignored by Git)
    2. From INACTIVE_USERS_SERVICE_EXCLUSIONS environment variable (comma or newline separated)
    3. Safe generic system defaults (Administrator, Guest, DefaultAccount, WDAGUtilityAccount)
    """
    instance_file = os.path.join(os.path.dirname(__file__), "instance", "service_accounts.txt")
    if os.path.exists(instance_file):
        try:
            with open(instance_file, "r", encoding="utf-8-sig") as f:
                accs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
                if accs:
                    return accs
        except Exception as e:
            logger.warning(f"Failed to read {instance_file}: {e}")

    env_val = os.getenv("INACTIVE_USERS_SERVICE_EXCLUSIONS", "").strip()
    if env_val:
        import re
        accs = [item.strip() for item in re.split(r"[,\r\n]+", env_val) if item.strip() and not item.strip().startswith("#")]
        if accs:
            return accs

    return [
        "Administrator",
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount",
    ]


DEFAULT_INACTIVE_USERS_SCRIPT = r'''param(
    [int]$InactiveMonths = 2
)

# SAFETY GUARD: Check if this server is a Domain Controller
$isDC = $false
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
    if ($os.ProductType -eq 2) { $isDC = $true }
} catch {
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os.ProductType -eq 2) { $isDC = $true }
    } catch {}
}

if ($isDC) {
    Write-Output "ABORT: Target is an Active Directory Domain Controller (ProductType=2). Inactive local user disabler cannot run on Domain Controllers."
    exit 0
}

$scriptFolder = "C:\Windows\Scripts\inactive_users"
$logFilePath = Join-Path $scriptFolder "DisabledUsersLog.txt"
$excludeFilePath = Join-Path $scriptFolder "excluded_users.txt"

$inactiveDate = (Get-Date).AddMonths(-$InactiveMonths)
Write-Output "Cutoff date for inactive accounts: $inactiveDate"

$excludedUsers = @()
if (Test-Path $excludeFilePath) {
    $excludedUsers = Get-Content -Path $excludeFilePath | Where-Object { $_.Trim() -ne '' -and $_.Trim() -notlike '#*' }
    Write-Output "Loaded $($excludedUsers.Count) excluded accounts."
} else {
    Write-Output "Exclusions file $excludeFilePath not found - no accounts excluded."
}

if (-not (Test-Path -Path $logFilePath)) {
    Out-File -FilePath $logFilePath -Encoding UTF8
}

$runStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
[System.IO.File]::AppendAllText($logFilePath, "--- Run started $runStart ---" + [Environment]::NewLine, [System.Text.Encoding]::UTF8)

$localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
$disabledCount = 0
$skippedExcluded = 0
$errorCount = 0

foreach ($user in $localUsers) {
    Write-Output "Checking user: $($user.Name)..."

    $isExcluded = $false
    foreach ($ex in $excludedUsers) {
        if ($user.Name -eq $ex.Trim()) {
            $isExcluded = $true
            break
        }
    }

    if ($isExcluded) {
        Write-Output "  Excluded (matches excluded_users.txt)."
        $skippedExcluded++
        continue
    }

    $lastLogon = $user.LastLogon
    $lastLogonDisplay = if ($null -eq $lastLogon) { "(never)" } else { $lastLogon }
    Write-Output "  Last logon: $lastLogonDisplay"

    if ($null -eq $lastLogon -or $lastLogon -lt $inactiveDate) {
        try {
            $user | Disable-LocalUser -ErrorAction Stop
            Write-Output "  Disabled."
            $disableDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "Account: $($user.Name) | Last logon: $lastLogonDisplay | Disabled on: $disableDate"
            [System.IO.File]::AppendAllText($logFilePath, $logEntry + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
            $disabledCount++
        } catch {
            $errEntry = "ERROR disabling $($user.Name): $($_.Exception.Message)"
            Write-Output "  $errEntry"
            [System.IO.File]::AppendAllText($logFilePath, $errEntry + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
            $errorCount++
        }
    }
}

$summary = "Summary: disabled=$disabledCount, excluded=$skippedExcluded, errors=$errorCount"
Write-Output $summary
[System.IO.File]::AppendAllText($logFilePath, $summary + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
'''


def build_inactive_users_exclusions(custom_service_accounts: Optional[List[str]] = None) -> str:
    """
    Dynamically generates excluded_users.txt content:
    - # Service accounts: loaded securely from local instance/ or env
    - # IT Support Group: active staff/admin usernames dynamically pulled from StaffMember in DB
    """
    from models import StaffMember
    lines = ["# Service accounts"]
    svc_accs = custom_service_accounts if custom_service_accounts is not None else get_service_accounts_exclusions()
    for acc in svc_accs:
        clean = (acc or "").strip()
        if clean:
            lines.append(clean)
    
    lines.append("# IT Support Group")
    try:
        active_staff = StaffMember.query.filter_by(is_active=True).order_by(StaffMember.username).all()
        for s in active_staff:
            u = (s.username or "").strip()
            if u and u.lower() not in [a.lower() for a in svc_accs]:
                lines.append(u)
    except Exception as ex:
        logger.warning(f"Failed to query StaffMember for exclusions: {ex}")

    return "\n".join(lines) + "\n"


def dispatch_task(app, task_type: str, playbook_name: str, host_ids: List[int], extra_vars: Dict[str, Any], user_id: Optional[int], summary: str, filter_info: str = "", exclude_host_ids: Optional[List[int]] = None) -> int:
    """Create TaskJob record and submit to thread pool with optional host exclusions."""
    from models import db, TaskJob, AuditLog

    # Apply exclusion filter if provided
    final_host_ids = [hid for hid in host_ids if hid not in (exclude_host_ids or [])]

    meta_info = {
        "playbook_name": playbook_name,
        "extra_vars": extra_vars,
        "note": filter_info,
        "excluded_hosts_count": len(host_ids) - len(final_host_ids) if exclude_host_ids else 0
    }
    stored_filter_info = json.dumps(meta_info, ensure_ascii=False)

    task = TaskJob(
        task_type=task_type,
        status="pending",
        summary=summary,
        filter_info=stored_filter_info,
        user_id=user_id,
        target_count=len(final_host_ids),
        created_at=datetime.utcnow()
    )
    db.session.add(task)
    
    audit = AuditLog(
        user_id=user_id,
        action=task_type.upper(),
        target=f"{len(final_host_ids)} hosts (excluded {len(host_ids) - len(final_host_ids)})",
        description=summary
    )
    db.session.add(audit)
    db.session.commit()

    # Dispatch to background thread
    executor.submit(run_ansible_task, app, task.id, playbook_name, final_host_ids, extra_vars)
    return task.id

