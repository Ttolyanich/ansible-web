import os
import sys
import yaml
import json

def test_syntax():
    print("--- 1. Testing YAML syntax of playbooks ---")
    playbooks = ["ping_check.yml", "user_create.yml", "user_delete.yml"]
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
        # Verify default admin
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None, "Admin user should exist!"
        assert admin.check_password("admin"), "Default password should be 'admin'"
        print("  [OK] Admin user verified.")

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
        # Setup 2 profiles for Linux: root (key) and itsgsrv (password)
        p_root = CredentialProfile(name="P_Root", os_type="linux", ssh_user="root", is_default=True, auth_type="key")
        p_root.private_key = "dummy-private-key"
        p_itsgsrv = CredentialProfile(name="P_Itsgsrv", os_type="linux", ssh_user="itsgsrv", is_default=False, auth_type="password")
        p_itsgsrv.password = "secret123"
        
        db.session.add(p_root)
        db.session.add(p_itsgsrv)
        db.session.commit()

        test_host = Host.query.filter_by(zabbix_hostid="test-host-1").first()
        assert test_host is not None

        cands = get_candidate_credentials(test_host, db.session)
        assert len(cands) >= 2, f"Expected at least 2 candidates, got {len(cands)}"
        assert cands[0]["user"] == "root", f"First candidate must be default (root), got {cands[0]['user']}"
        assert cands[0]["auth_type"] == "key"
        
        # Check that itsgsrv is among fallback candidates
        itsg_cand = next((c for c in cands if c["user"] == "itsgsrv"), None)
        assert itsg_cand is not None, "itsgsrv must be in fallback candidate list!"
        assert itsg_cand["auth_type"] == "password"
        assert itsg_cand["password"] == "secret123"

        print(f"  [OK] Fallback candidate credentials verified: {[c['user'] + ' (' + c['auth_type'] + ')' for c in cands]}")

        db.session.delete(p_root)
        db.session.delete(p_itsgsrv)
        db.session.commit()

if __name__ == "__main__":
    try:
        test_syntax()
        test_models_and_crypto()
        test_database_and_bootstrap()
        test_inventory_generation()
        test_candidate_credentials_fallback()
        print("\n==========================================")
        print(">>> ALL SYSTEM TESTS PASSED SUCCESSFULLY! <<<")
        print("==========================================")
    except Exception as e:
        print(f"\n[FAIL] Test Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
