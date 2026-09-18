import os
import sys
import yaml
import json

def test_syntax():
    print("--- 1. Testing YAML syntax of playbooks ---")
    playbooks = [
        "ping_check.yml", "user_create.yml", "user_delete.yml",
        "system_update.yml", "service_restart.yml", "disk_space_audit.yml", "docker_cleanup.yml"
    ]
    for pb in playbooks:
        path = os.path.join(os.path.dirname(__file__), "playbooks", pb)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            assert isinstance(data, list), f"Playbook {pb} root must be a list"
            print(f"  [OK] {pb} valid YAML syntax.")

def test_models_and_crypto():
    print("\n--- 2. Testing Models & Fernet Crypto ---")
    from models import CryptoHelper
    test_secret = "super-secret-ssh-key-or-password-123!"
    encrypted = CryptoHelper.encrypt(test_secret)
    decrypted = CryptoHelper.decrypt(encrypted)
    assert decrypted == test_secret, "Decrypted text must match original!"
    print("  [OK] Fernet encryption and decryption works perfectly.")

def test_database_and_bootstrap():
    print("\n--- 3. Testing Flask App & Database Bootstrap ---")
    from app import app, db
    from models import User, CredentialProfile, ZabbixSetting, Host, HostGroup

    with app.app_context():
        # Verify admin user
        admin = User.query.filter_by(role="admin").first() or User.query.first()
        if not admin:
            admin = User(username="admin", role="admin")
            admin.set_password("admin")
            db.session.add(admin)
            db.session.commit()
        assert admin is not None, "Admin user should exist!"
        print(f"  [OK] Admin user verified ({admin.username}).")

        # Verify Zabbix setting
        setting = ZabbixSetting.query.first()
        assert setting is not None, "Zabbix setting should exist!"
        print("  [OK] Zabbix settings record exists.")

        # Test creating and editing a custom credential profile dynamically
        cp = CredentialProfile(name="Custom Test Profile", os_type="linux", ssh_user="myuser", ssh_port=2222)
        db.session.add(cp)
        db.session.commit()
        assert cp.id is not None
        # Test edit
        cp.name = "Custom Test Profile Edited"
        cp.ssh_port = 22
        db.session.commit()
        loaded = db.session.get(CredentialProfile, cp.id)
        assert loaded.name == "Custom Test Profile Edited"
        assert loaded.ssh_port == 22
        db.session.delete(loaded)
        db.session.commit()
        print("  [OK] Dynamic credential profile creation and editing verified.")

def test_inventory_generation():
    print("\n--- 4. Testing Dynamic Inventory Generation ---")
    from app import app, db
    from models import Host, HostGroup, CredentialProfile
    from task_engine import generate_inventory
    import tempfile
    import shutil

    with app.app_context():
        # Create dummy group and hosts
        grp = HostGroup.query.filter_by(zabbix_groupid="test-grp-1").first()
        if not grp:
            grp = HostGroup(zabbix_groupid="test-grp-1", name="Test Company LLC")
            db.session.add(grp)
            db.session.flush()

        h_linux = Host.query.filter_by(zabbix_hostid="test-host-1").first()
        if not h_linux:
            h_linux = Host(
                zabbix_hostid="test-host-1",
                name="test-deb-srv01",
                ip_address="192.168.10.15",
                os_type="linux",
                group_id=grp.id
            )
            db.session.add(h_linux)

        h_win = Host.query.filter_by(zabbix_hostid="test-host-2").first()
        if not h_win:
            h_win = Host(
                zabbix_hostid="test-host-2",
                name="test-win-srv01",
                ip_address="192.168.10.20",
                os_type="windows",
                group_id=grp.id
            )
            db.session.add(h_win)

        db.session.commit()

        temp_dir = tempfile.mkdtemp()
        inv_file = generate_inventory([h_linux, h_win], temp_dir, db.session)
        assert os.path.exists(inv_file), "Inventory file must exist"
        
        with open(inv_file, "r", encoding="utf-8") as f:
            inv_data = yaml.safe_load(f)

        assert "all" in inv_data and "hosts" in inv_data["all"]
        hosts = inv_data["all"]["hosts"]
        assert "test-deb-srv01" in hosts
        assert hosts["test-deb-srv01"]["ansible_host"] == "192.168.10.15"
        assert hosts["test-deb-srv01"]["os_type"] == "linux"
        assert "test-win-srv01" in hosts
        assert hosts["test-win-srv01"]["ansible_user"] == "Administrator"
        assert hosts["test-win-srv01"]["os_type"] == "windows"
        
        print(f"  [OK] Dynamic inventory generated and validated:\n{yaml.dump(inv_data, default_flow_style=False)}")
        shutil.rmtree(temp_dir)

def test_candidate_credentials_fallback():
    print("\n--- 5. Testing Candidate Credentials Fallback Resolution ---")
    from app import app, db
    from models import Host, CredentialProfile
    from task_engine import get_candidate_credentials

    with app.app_context():
        # Setup 2 profiles for Linux: root (key) and sysadmin (password)
        p_root = CredentialProfile(name="P_Root", os_type="linux", ssh_user="root", is_default=True, auth_type="key")
        p_root.private_key = "dummy-private-key"
        p_sysadmin = CredentialProfile(name="P_Sysadmin", os_type="linux", ssh_user="sysadmin", is_default=False, auth_type="password")
        p_sysadmin.password = "secret123"
        
        db.session.add(p_root)
        db.session.add(p_sysadmin)
        db.session.commit()

        test_host = Host.query.filter_by(zabbix_hostid="test-host-1").first()
        assert test_host is not None

        cands = get_candidate_credentials(test_host, db.session)
        assert len(cands) >= 2, f"Expected at least 2 candidates, got {len(cands)}"
        assert cands[0]["user"] == "root", f"First candidate must be default (root), got {cands[0]['user']}"
        assert cands[0]["auth_type"] == "key"
        
        # Check that sysadmin is among fallback candidates
        sysadmin_cand = next((c for c in cands if c["user"] == "sysadmin"), None)
        assert sysadmin_cand is not None, "sysadmin must be in fallback candidate list!"
        assert sysadmin_cand["auth_type"] == "password"
        assert sysadmin_cand["password"] == "secret123"

        print(f"  [OK] Fallback candidate credentials verified: {[c['user'] + ' (' + c['auth_type'] + ')' for c in cands]}")

        db.session.delete(p_root)
        db.session.delete(p_sysadmin)
        db.session.commit()

def test_vpn_extraction_and_manual_override():
    print("\n--- 6. Testing VPN IP Extraction from Comments & Manual Override ---")
    from zabbix_client import extract_vpn_ip_from_comment
    from app import app, db
    from models import Host

    # Test parser
    assert extract_vpn_ip_from_comment("VPN: 10.0.0.10") == "10.0.0.10"
    assert extract_vpn_ip_from_comment("Хост за прокси. впн: 10.0.1.5") == "10.0.1.5"
    assert extract_vpn_ip_from_comment("10.0.0.12") == "10.0.0.12"
    assert extract_vpn_ip_from_comment("WireGuard 10.10.0.44") == "10.10.0.44"
    assert extract_vpn_ip_from_comment("IP VPN: 172.16.20.5") == "172.16.20.5"
    assert extract_vpn_ip_from_comment("127.0.0.1") is None
    assert extract_vpn_ip_from_comment("Комментарий без IP") is None
    print("  [OK] extract_vpn_ip_from_comment regex tests passed.")

    with app.app_context():
        h = Host.query.filter_by(zabbix_hostid="test-host-vpn").first()
        if not h:
            h = Host(
                zabbix_hostid="test-host-vpn",
                name="test-vpn-srv",
                ip_address="10.0.0.10",
                is_ip_manually_set=True,
                ip_source="manual",
                zabbix_agent_ip="192.168.1.50"
            )
            db.session.add(h)
            db.session.commit()

        assert h.is_ip_manually_set is True
        assert h.ip_source == "manual"
        db.session.delete(h)
        db.session.commit()
        print("  [OK] Host manual override fields verified.")

def test_ssh_port_handling():
    print("\n--- 7. Testing Custom SSH Port Parsing & Host Port Inheritance ---")
    from zabbix_client import extract_port_from_comment
    from app import app, db
    from models import Host
    from task_engine import resolve_credentials, get_candidate_credentials, generate_inventory
    import tempfile
    import shutil

    # 1. Test port extraction from comments
    assert extract_port_from_comment("10.0.0.10:2222") == 2222
    assert extract_port_from_comment("Хост за NAT. порт 2202") == 2202
    assert extract_port_from_comment("port: 22222") == 22222
    assert extract_port_from_comment("ssh port 8022") == 8022
    assert extract_port_from_comment("ssh: 2222") == 2222
    assert extract_port_from_comment("порт: 99999") is None # Out of range > 65535
    assert extract_port_from_comment("Обычный сервер без порта") is None
    print("  [OK] extract_port_from_comment regex tests passed.")

    # 2. Test port inheritance in inventory and credentials
    with app.app_context():
        h = Host(
            zabbix_hostid="test-host-port-custom",
            name="test-port-srv",
            ip_address="10.0.0.15",
            ssh_port=2222,
            os_type="linux"
        )
        db.session.add(h)
        db.session.commit()

        creds = resolve_credentials(h, db.session)
        assert creds["port"] == 2222, f"Expected port 2222 in resolved creds, got {creds.get('port')}"

        cands = get_candidate_credentials(h, db.session)
        assert all(c["port"] == 2222 for c in cands), "All candidate credentials must inherit custom host port 2222"

        temp_dir = tempfile.mkdtemp()
        inv_file = generate_inventory([h], temp_dir, db.session)
        with open(inv_file, "r", encoding="utf-8") as f:
            inv = yaml.safe_load(f)
        assert inv["all"]["hosts"]["test-port-srv"]["ansible_port"] == 2222
        shutil.rmtree(temp_dir)

        db.session.delete(h)
        db.session.commit()
        print("  [OK] Host custom SSH port inheritance in credentials and inventory verified.")

def test_os_detection_and_manual_preservation():
    print("\n--- 8. Testing OS Detection (Network/TP-Link/Linux/Win) & Manual Preservation ---")
    from zabbix_client import detect_os_type
    from app import app, db
    from models import Host

    # 1. Test detect_os_type heuristics
    assert detect_os_type([], "tp-link-24g") == "network"
    assert detect_os_type([], "office-tp-link-switch") == "network"
    assert detect_os_type(["Template Net TP-LINK by SNMP"], "office-sw01") == "network"
    assert detect_os_type([], "sw-cisco-core") == "network"
    assert detect_os_type([], "rt-mikrotik-main") == "network"
    assert detect_os_type(["Linux by Zabbix agent"], "tp-link-mon") == "linux"
    assert detect_os_type([], "srv-deb-01") == "linux"
    assert detect_os_type([], "srv-lin-web") == "linux"
    assert detect_os_type([], "dc01-win-srv") == "windows"
    assert detect_os_type([], "unknown-server") == "unknown"
    print("  [OK] detect_os_type heuristics passed (TP-Link is network, not Linux).")

    # 2. Test manual OS preservation
    with app.app_context():
        h = Host(
            zabbix_hostid="test-host-manual-os",
            name="tp-link-office",
            ip_address="10.0.0.16",
            os_type="network",
            is_os_manually_set=True
        )
        db.session.add(h)
        db.session.commit()

        assert h.is_os_manually_set is True
        assert h.os_type == "network"

        db.session.delete(h)
        db.session.commit()
        print("  [OK] Host is_os_manually_set flag verified.")

def test_ssh_key_normalization_and_ping_escalation():
    print("\n--- 9. Testing SSH Key Normalization & Ping Become Bypass ---")
    from task_engine import normalize_private_key, write_clean_key_file, generate_inventory
    from app import app, db
    from models import Host, HostGroup, CredentialProfile
    import tempfile

    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    # 1. Test normalize_private_key with real key
    real_ed = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()
    ).decode("utf-8")
    crlf_key = real_ed.replace("\n", "\r\n")
    normalized = normalize_private_key(crlf_key)
    assert "\r" not in normalized, "Carriage returns must be stripped!"
    assert normalized.endswith("\n"), "Must end with newline"
    print("  [OK] normalize_private_key correctly strips CRLF.")

    # 2. Test write_clean_key_file
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "test_key")
        write_clean_key_file(crlf_key, "", target)
        assert os.path.exists(target)
        with open(target, "rb") as f:
            content = f.read()
            assert b"\r" not in content, "Written key must have no CRLF!"
    print("  [OK] write_clean_key_file writes clean binary key without CRLF.")

    # 3. Test inventory generate with is_ping=True
    with app.app_context():
        grp = HostGroup.query.first()
        h = Host.query.filter_by(zabbix_hostid="test-ping-host").first()
        if not h:
            h = Host(
                zabbix_hostid="test-ping-host",
                name="test-ping-host",
                ip_address="10.0.0.25",
                os_type="linux",
                group_id=grp.id if grp else None
            )
            db.session.add(h)
            db.session.commit()

        creds = {
            "auth_type": "key",
            "user": "sysadmin",
            "private_key": crlf_key,
            "become_method": "sudo",
            "sudo_password": ""
        }

        with tempfile.TemporaryDirectory() as td:
            # Ping mode -> no become!
            inv_ping = generate_inventory([h], td, db.session, host_creds_map={str(h.id): creds}, is_ping=True)
            with open(inv_ping, "r") as f:
                data = yaml.safe_load(f)
                hvars = data["all"]["hosts"]["test-ping-host"]
                assert "ansible_become" not in hvars, "ansible_become must NOT be set when is_ping=True!"

            # Normal mode -> become set!
            inv_run = generate_inventory([h], td, db.session, host_creds_map={str(h.id): creds}, is_ping=False)
            with open(inv_run, "r") as f:
                data = yaml.safe_load(f)
                hvars = data["all"]["hosts"]["test-ping-host"]
                assert hvars.get("ansible_become") is True, "ansible_become MUST be set when is_ping=False!"

        db.session.delete(h)
        db.session.commit()
    print("  [OK] is_ping bypass for privilege escalation verified.")

    # 4. Test validate_ssh_key
    from task_engine import validate_ssh_key
    valid_pub, err_pub = validate_ssh_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@test")
    assert not valid_pub and "открытый" in err_pub, "Should reject public key!"

    valid_ppk, err_ppk = validate_ssh_key("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none")
    assert not valid_ppk and "PuTTY" in err_ppk, "Should reject PPK format!"
    print("  [OK] validate_ssh_key rejects public keys and PPK formats.")

def test_audit_security_fixes():
    print("\n--- 10. Testing Audit Security Fixes (P0/P1/P2) ---")
    from app import is_valid_username, validate_safe_extra_vars
    from task_engine import sanitize_extra_vars_for_storage, DEFAULT_INACTIVE_USERS_SCRIPT

    # 1. Username policy
    assert is_valid_username("a.ivanov") is True
    assert is_valid_username("user_123") is True
    assert is_valid_username("0") is False, "Numeric username '0' must be rejected"
    assert is_valid_username("12345") is False, "Numeric username '12345' must be rejected"
    assert is_valid_username("-admin") is False, "Username starting with hyphen must be rejected"
    assert is_valid_username("a") is False, "Single character username must be rejected"
    assert is_valid_username("a" * 33) is False, "Username over 32 chars must be rejected"
    print("  [OK] is_valid_username strict POSIX policy verified.")

    # 2. Safe extra_vars policy
    assert validate_safe_extra_vars({"target_service": "nginx", "service_state": "restarted"})[0] is True
    assert validate_safe_extra_vars({"ansible_ssh_common_args": "-o ProxyCommand=evil"})[0] is False
    assert validate_safe_extra_vars({"ansible_python_interpreter": "/bin/sh"})[0] is False
    assert validate_safe_extra_vars({"effective_users": [{"username": "hacked"}]})[0] is False
    assert validate_safe_extra_vars({"bad key!": "val"})[0] is False
    print("  [OK] validate_safe_extra_vars injection prevention verified.")

    # 3. Secret scrubbing for filter_info / DB persistence
    sample = {
        "target_users": [{"username": "john", "password": "SuperSecretPassword123!", "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnopqrstuvwxyz0123456789 user@host"}],
        "normal_var": 123,
        "token": "secret_token_abc"
    }
    sanitized = sanitize_extra_vars_for_storage(sample)
    assert sanitized["target_users"][0]["password"] == "******"
    assert sanitized["token"] == "******"
    assert sanitized["normal_var"] == 123
    assert "TRUNCATED" in sanitized["target_users"][0]["ssh_key"]
    print("  [OK] sanitize_extra_vars_for_storage verified.")

    # 4. Inactive users script hardening
    assert "FAIL-CLOSE: Unable to verify Operating System ProductType" in DEFAULT_INACTIVE_USERS_SCRIPT
    assert "CRITICAL: Exclusions file" in DEFAULT_INACTIVE_USERS_SCRIPT
    assert "PasswordLastSet" in DEFAULT_INACTIVE_USERS_SCRIPT
    print("  [OK] DEFAULT_INACTIVE_USERS_SCRIPT Fail-Close and fresh account safety verified.")

if __name__ == "__main__":
    try:
        test_syntax()
        test_models_and_crypto()
        test_database_and_bootstrap()
        test_inventory_generation()
        test_candidate_credentials_fallback()
        test_vpn_extraction_and_manual_override()
        test_ssh_port_handling()
        test_os_detection_and_manual_preservation()
        test_ssh_key_normalization_and_ping_escalation()
        test_audit_security_fixes()
        print("\n==========================================")
        print(">>> ALL SYSTEM TESTS PASSED SUCCESSFULLY! <<<")
        print("==========================================")
    except Exception as e:
        print(f"\n[FAIL] Test Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
