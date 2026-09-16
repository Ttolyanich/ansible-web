import os
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, MultiFernet

db = SQLAlchemy()

class CryptoHelper:
    """Helper for symmetric encryption/decryption of sensitive credentials."""
    _cipher = None

    @classmethod
    def get_cipher(cls):
        if cls._cipher is None:
            key = os.getenv("FERNET_KEY")
            if not key:
                # Fallback to persistent key in instance/fernet.key
                key_path = os.path.join(os.path.dirname(__file__), "instance", "fernet.key")
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                if os.path.exists(key_path):
                    with open(key_path, "rb") as f:
                        key = f.read().decode().strip()
                else:
                    new_key = Fernet.generate_key().decode()
                    with open(key_path, "wb") as f:
                        f.write(new_key.encode())
                    try:
                        os.chmod(key_path, 0o600)
                    except Exception:
                        pass
                    key = new_key
            primary_key = key.encode() if isinstance(key, str) else key
            ciphers = [Fernet(primary_key)]
            legacy_key = b"v1tX7e1eHnZtTqK_x6FvE9qL1pG2bA4sD6jK8mN0wQY="
            if primary_key != legacy_key:
                ciphers.append(Fernet(legacy_key))
            cls._cipher = MultiFernet(ciphers)
        return cls._cipher

    @classmethod
    def encrypt(cls, text: str) -> str:
        if not text:
            return ""
        cipher = cls.get_cipher()
        return cipher.encrypt(text.encode("utf-8")).decode("utf-8")

    @classmethod
    def decrypt(cls, token: str) -> str:
        if not token:
            return ""
        cipher = cls.get_cipher()
        try:
            return cipher.decrypt(token.encode("utf-8")).decode("utf-8")
        except Exception:
            return ""


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="operator") # 'admin' or 'operator'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class StaffMember(db.Model):
    __tablename__ = "staff_members"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    ssh_public_key = db.Column(db.Text, nullable=True)
    encrypted_password = db.Column(db.Text, nullable=True)
    sudo_enabled = db.Column(db.Boolean, default=True)
    department = db.Column(db.String(100), nullable=True)
    is_system = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_password)

    @password.setter
    def password(self, val: str):
        self.encrypted_password = CryptoHelper.encrypt(val) if val else ""

    def key_fingerprint_short(self) -> str:
        if not self.ssh_public_key:
            return "Без ключа"
        parts = self.ssh_public_key.strip().split()
        if len(parts) >= 2:
            ktype = parts[0]
            kbody = parts[1]
            return f"{ktype} ...{kbody[-12:]}"
        return "SSH-ключ задан"


class ZabbixSetting(db.Model):
    __tablename__ = "zabbix_settings"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False, default="http://zabbix-server/api_jsonrpc.php")

    encrypted_token = db.Column(db.Text, nullable=True) # API Token
    verify_ssl = db.Column(db.Boolean, default=False)
    auto_sync = db.Column(db.Boolean, default=False)
    sync_interval_mins = db.Column(db.Integer, default=60)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(50), default="never")
    last_sync_message = db.Column(db.Text, nullable=True)
    last_sync_count = db.Column(db.Integer, default=0)

    @property
    def token(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_token)

    @token.setter
    def token(self, val: str):
        self.encrypted_token = CryptoHelper.encrypt(val) if val else ""


class CredentialProfile(db.Model):
    """SSH Credentials Profile (e.g. Linux root, Linux sysadmin, Windows Administrator)."""
    __tablename__ = "credential_profiles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) # e.g. "Default Linux (root)"
    os_type = db.Column(db.String(20), nullable=False, default="linux") # 'linux' or 'windows'
    ssh_user = db.Column(db.String(80), nullable=False, default="root")
    ssh_port = db.Column(db.Integer, nullable=False, default=22)
    auth_type = db.Column(db.String(20), default="key") # 'key' or 'password'
    
    encrypted_private_key = db.Column(db.Text, nullable=True)
    encrypted_passphrase = db.Column(db.Text, nullable=True)
    encrypted_password = db.Column(db.Text, nullable=True)
    encrypted_sudo_password = db.Column(db.Text, nullable=True)
    
    become_method = db.Column(db.String(20), default="sudo") # 'sudo', 'su', 'none'
    is_default = db.Column(db.Boolean, default=False) # default profile for this os_type
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Decrypted property accessors
    @property
    def private_key(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_private_key)

    @private_key.setter
    def private_key(self, val: str):
        self.encrypted_private_key = CryptoHelper.encrypt(val) if val else ""

    @property
    def passphrase(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_passphrase)

    @passphrase.setter
    def passphrase(self, val: str):
        self.encrypted_passphrase = CryptoHelper.encrypt(val) if val else ""

    @property
    def password(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_password)

    @password.setter
    def password(self, val: str):
        self.encrypted_password = CryptoHelper.encrypt(val) if val else ""

    @property
    def sudo_password(self) -> str:
        return CryptoHelper.decrypt(self.encrypted_sudo_password)

    @sudo_password.setter
    def sudo_password(self, val: str):
        self.encrypted_sudo_password = CryptoHelper.encrypt(val) if val else ""


class HostGroup(db.Model):
    """Zabbix Host Group (representing a company / department)."""
    __tablename__ = "host_groups"
    id = db.Column(db.Integer, primary_key=True)
    zabbix_groupid = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    credential_id = db.Column(db.Integer, db.ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True)
    
    credential = db.relationship("CredentialProfile", foreign_keys=[credential_id])
    hosts = db.relationship("Host", backref="group", lazy="dynamic", cascade="all, delete-orphan")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Host(db.Model):
    """Target Server."""
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    zabbix_hostid = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    ssh_port = db.Column(db.Integer, nullable=True) # Custom SSH port override (e.g. 2222)
    is_ip_manually_set = db.Column(db.Boolean, default=False)
    ip_source = db.Column(db.String(30), default="zabbix") # 'zabbix', 'vpn_comment', 'manual'
    zabbix_agent_ip = db.Column(db.String(100), default="") # original interface IP from Zabbix
    zabbix_description = db.Column(db.Text, default="") # host comment from Zabbix
    proxy_hostid = db.Column(db.String(50), default="0") # Zabbix proxy ID if behind proxy
    os_type = db.Column(db.String(20), default="unknown") # 'linux', 'windows', 'network', 'unknown'
    is_os_manually_set = db.Column(db.Boolean, default=False) # Protected from Zabbix auto-detection override
    zabbix_templates = db.Column(db.Text, default="")
    group_id = db.Column(db.Integer, db.ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True)
    credential_id = db.Column(db.Integer, db.ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True)
    
    override_credential = db.relationship("CredentialProfile", foreign_keys=[credential_id])
    last_status = db.Column(db.String(20), default="unknown") # 'online', 'offline', 'unknown'
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    is_enabled = db.Column(db.Boolean, default=True)
    is_ignored = db.Column(db.Boolean, default=False) # True for iDRAC, IPMI, NAS, Network, UPS, etc.
    is_ignored_manually_set = db.Column(db.Boolean, default=False)
    device_type = db.Column(db.String(50), default="server") # 'server', 'idrac_ipmi', 'nas', 'network', 'ups', 'other'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TaskJob(db.Model):
    """Background execution job (Ansible or Sync)."""
    __tablename__ = "task_jobs"
    id = db.Column(db.Integer, primary_key=True)
    task_type = db.Column(db.String(50), nullable=False) # 'ping', 'user_create', 'user_delete', 'zabbix_sync'
    status = db.Column(db.String(20), default="pending") # 'pending', 'running', 'success', 'failed', 'partial'
    summary = db.Column(db.String(255), default="")
    filter_info = db.Column(db.Text, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    user = db.relationship("User")
    target_count = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    
    log_output = db.Column(db.Text, default="")
    details_json = db.Column(db.Text, default="{}") # Host-by-host result breakdown
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def details(self):
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    @details.setter
    def details(self, val):
        self.details_json = json.dumps(val, ensure_ascii=False)


class AuditLog(db.Model):
    """Audit log for user operations."""
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    user = db.relationship("User")
    action = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
