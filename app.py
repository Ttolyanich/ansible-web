import os
import json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

# Load environment variables
load_dotenv()

from models import (
    db, User, ZabbixSetting, CredentialProfile, 
    HostGroup, Host, TaskJob, AuditLog
)
from zabbix_client import ZabbixClient, sync_zabbix_to_db
from task_engine import dispatch_task, enable_openssl_legacy_provider

enable_openssl_legacy_provider()


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "ansible-super-secret-key-default-change-me")
db_url = os.getenv("DATABASE_URL")
if not db_url:
    instance_dir = os.path.join(os.path.dirname(__file__), "instance")
    os.makedirs(instance_dir, exist_ok=True)
    db_url = f"sqlite:///{os.path.join(instance_dir, 'ansible_web.db')}"
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Пожалуйста, войдите в систему для доступа к панели."
login_manager.login_message_category = "info"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("У вас нет прав администратора для выполнения этого действия.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------
# Background Scheduler for Auto Zabbix Sync
# -------------------------------------------------------------
scheduler = BackgroundScheduler(daemon=True)

def scheduled_zabbix_sync():
    with app.app_context():
        setting = ZabbixSetting.query.first()
        if setting and setting.auto_sync and setting.url and setting.token:
            sync_zabbix_to_db(db.session, setting, user_id=None)

scheduler.add_job(scheduled_zabbix_sync, 'interval', minutes=60, id='zabbix_sync_job')
scheduler.start()


# -------------------------------------------------------------
# Favicon Route
# -------------------------------------------------------------
@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.svg",
        mimetype="image/svg+xml"
    )


# -------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash("Данная учетная запись заблокирована.", "danger")
                return render_template("login.html")
            login_user(user)
            flash(f"Добро пожаловать, {user.username}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        flash("Неверное имя пользователя или пароль.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы успешно вышли из системы.", "info")
    return redirect(url_for("login"))


# -------------------------------------------------------------
# Dashboard & Overview
# -------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    total_hosts = Host.query.filter_by(is_enabled=True).count()
    online_hosts = Host.query.filter_by(is_enabled=True, last_status="online").count()
    offline_hosts = Host.query.filter_by(is_enabled=True, last_status="offline").count()
    unknown_hosts = Host.query.filter_by(is_enabled=True, last_status="unknown").count()
    linux_hosts = Host.query.filter_by(is_enabled=True, os_type="linux").count()
    windows_hosts = Host.query.filter_by(is_enabled=True, os_type="windows").count()
    network_hosts = Host.query.filter_by(is_enabled=True, os_type="network").count()

    stats = {
        "total": total_hosts,
        "online": online_hosts,
        "offline": offline_hosts,
        "unknown": unknown_hosts,
        "linux": linux_hosts,
        "windows": windows_hosts,
        "network": network_hosts
    }

    groups = HostGroup.query.order_by(HostGroup.name).all()
    recent_tasks = TaskJob.query.order_by(TaskJob.id.desc()).limit(5).all()
    zabbix_setting = ZabbixSetting.query.first()

    return render_template(
        "dashboard.html",
        stats=stats,
        groups=groups,
        recent_tasks=recent_tasks,
        zabbix_setting=zabbix_setting
    )


# -------------------------------------------------------------
# Hosts Management & Filtering
# -------------------------------------------------------------
@app.route("/hosts")
@login_required
def hosts_view():
    query = Host.query.filter_by(is_enabled=True)

    filter_q = request.args.get("q", "").strip()
    filter_group_id = request.args.get("group_id", "").strip()
    filter_os = request.args.get("os", "").strip()
    filter_status = request.args.get("status", "").strip()

    if filter_q:
        query = query.filter(
            (Host.name.ilike(f"%{filter_q}%")) | (Host.ip_address.ilike(f"%{filter_q}%"))
        )
    if filter_group_id:
        query = query.filter_by(group_id=int(filter_group_id))
    if filter_os:
        query = query.filter_by(os_type=filter_os)
    if filter_status:
        query = query.filter_by(last_status=filter_status)

    hosts = query.order_by(Host.name).all()
    groups = HostGroup.query.order_by(HostGroup.name).all()

    return render_template(
        "hosts.html",
        hosts=hosts,
        groups=groups,
        filter_q=filter_q,
        filter_group_id=filter_group_id,
        filter_os=filter_os,
        filter_status=filter_status
    )

@app.route("/hosts/<int:host_id>", methods=["GET", "POST"])
@login_required
def host_detail(host_id):
    host = db.get_or_404(Host, host_id)
    credential_profiles = CredentialProfile.query.order_by(CredentialProfile.name).all()

    if request.method == "POST":
        action = request.form.get("action", "save")
        
        if action == "reset_ip":
            # Revert to automatic IP & Port (VPN from comment if present, else original Zabbix agent IP)
            host.is_ip_manually_set = False
            from zabbix_client import extract_vpn_ip_from_comment, extract_port_from_comment
            vpn_ip = extract_vpn_ip_from_comment(host.zabbix_description)
            vpn_port = extract_port_from_comment(host.zabbix_description)
            host.ssh_port = vpn_port
            if vpn_ip:
                host.ip_address = vpn_ip
                host.ip_source = "vpn_comment"
            elif host.zabbix_agent_ip:
                host.ip_address = host.zabbix_agent_ip
                host.ip_source = "zabbix"
            db.session.commit()
            port_str = f":{host.ssh_port}" if host.ssh_port else ""
            flash(f"Параметры подключения хоста {host.name} сброшены на значения из Zabbix ({host.ip_address}{port_str}).", "info")
            return redirect(url_for("host_detail", host_id=host.id))

        if action == "reset_os":
            host.is_os_manually_set = False
            from zabbix_client import detect_os_type
            templates = [t.strip() for t in (host.zabbix_templates or "").split(",") if t.strip()]
            host.os_type = detect_os_type(templates, host.name)
            db.session.commit()
            flash(f"Тип ОС хоста {host.name} сброшен на автоопределение ({host.os_type}).", "info")
            return redirect(url_for("host_detail", host_id=host.id))

        new_ip = request.form.get("ip_address", host.ip_address).strip()
        if new_ip and new_ip != host.ip_address:
            host.ip_address = new_ip
            host.is_ip_manually_set = True
            host.ip_source = "manual"

        # SSH Port override
        raw_port = request.form.get("ssh_port", "").strip()
        if raw_port and raw_port.isdigit():
            host.ssh_port = int(raw_port)
        elif raw_port == "":
            host.ssh_port = None

        new_os = request.form.get("os_type", host.os_type)
        if new_os and new_os != host.os_type:
            host.os_type = new_os
            host.is_os_manually_set = True

        cred_id = request.form.get("credential_id")
        host.credential_id = int(cred_id) if cred_id else None
        
        db.session.commit()
        flash(f"Настройки хоста {host.name} успешно обновлены.", "success")
        return redirect(url_for("host_detail", host_id=host.id))

    return render_template(
        "host_detail.html",
        host=host,
        credential_profiles=credential_profiles
    )


# -------------------------------------------------------------
# Ping / Availability Check
# -------------------------------------------------------------
@app.route("/ping/all", methods=["POST"])
@login_required
def run_ping_all():
    hosts = Host.query.filter_by(is_enabled=True).all()
    if not hosts:
        flash("Нет активных хостов для проверки.", "warning")
        return redirect(url_for("dashboard"))

    host_ids = [h.id for h in hosts]
    task_id = dispatch_task(
        app=app,
        task_type="ping",
        playbook_name="ping_check.yml",
        host_ids=host_ids,
        extra_vars={},
        user_id=current_user.id,
        summary=f"Быстрая SSH проверка доступности ({len(host_ids)} хостов)",
        filter_info="Все хосты"
    )
    flash(f"Запущена проверка доступности для {len(host_ids)} хостов.", "info")
    return redirect(url_for("task_detail", task_id=task_id))

@app.route("/ping/batch", methods=["POST"])
@login_required
def run_ping_batch():
    raw_ids = request.form.getlist("host_ids")
    if not raw_ids:
        flash("Не выбраны хосты для проверки.", "warning")
        return redirect(url_for("hosts_view"))

    host_ids = [int(i) for i in raw_ids if i.isdigit()]
    task_id = dispatch_task(
        app=app,
        task_type="ping",
        playbook_name="ping_check.yml",
        host_ids=host_ids,
        extra_vars={},
        user_id=current_user.id,
        summary=f"Выборочная SSH проверка ({len(host_ids)} хостов)",
        filter_info=f"Выбрано хостов: {len(host_ids)}"
    )
    flash(f"Запущена проверка доступности для {len(host_ids)} хостов.", "info")
    return redirect(url_for("task_detail", task_id=task_id))


# -------------------------------------------------------------
# User Operations (Create & Delete Master)
# -------------------------------------------------------------
@app.route("/user-ops", methods=["GET", "POST"])
@login_required
def user_ops_view():
    selected_host_ids = []
    if request.method == "POST":
        # Coming from hosts table batch checkbox action
        selected_host_ids = request.form.getlist("host_ids")
    else:
        group_id_param = request.args.get("group_id")
        if group_id_param and group_id_param.isdigit():
            group_hosts = Host.query.filter_by(group_id=int(group_id_param), is_enabled=True).all()
            selected_host_ids = [str(h.id) for h in group_hosts]

    groups = HostGroup.query.order_by(HostGroup.name).all()
    all_hosts_count = Host.query.filter_by(is_enabled=True).count()

    return render_template(
        "user_ops.html",
        groups=groups,
        all_hosts_count=all_hosts_count,
        selected_host_ids=selected_host_ids,
        selected_group_id=request.args.get("group_id", "")
    )

@app.route("/user-ops/run", methods=["POST"])
@login_required
def run_user_ops():
    operation = request.form.get("operation", "create") # 'create' or 'delete'
    target_type = request.form.get("target_type", "all") # 'all', 'group', 'preselected'
    target_os = request.form.get("target_os", "all") # 'all', 'linux', 'windows'
    target_username = request.form.get("target_username", "").strip()

    if not target_username:
        flash("Имя пользователя обязательно для заполнения.", "danger")
        return redirect(url_for("user_ops_view"))

    # Determine target hosts
    query = Host.query.filter_by(is_enabled=True)

    if target_type == "preselected":
        ids_json = request.form.get("selected_host_ids_json", "[]")
        try:
            ids_list = [int(i) for i in json.loads(ids_json) if str(i).isdigit()]
        except Exception:
            ids_list = []
        if not ids_list:
            flash("Список выбранных хостов пуст.", "danger")
            return redirect(url_for("user_ops_view"))
        query = query.filter(Host.id.in_(ids_list))
    elif target_type == "group":
        group_id = request.form.get("group_id")
        if not group_id:
            flash("Не выбрана целевая группа.", "danger")
            return redirect(url_for("user_ops_view"))
        query = query.filter_by(group_id=int(group_id))

    if target_os in ("linux", "windows"):
        query = query.filter_by(os_type=target_os)

    target_hosts = query.all()
    if not target_hosts:
        flash("Не найдено хостов, соответствующих критериям выборки.", "warning")
        return redirect(url_for("user_ops_view"))

    host_ids = [h.id for h in target_hosts]

    # Prepare Playbook & Extra Vars
    if operation == "create":
        playbook_name = "user_create.yml"
        target_ssh_key = request.form.get("target_ssh_key", "").strip()
        target_password = request.form.get("target_password", "").strip()
        target_sudo = request.form.get("target_sudo") == "1"

        extra_vars = {
            "target_username": target_username,
            "target_ssh_key": target_ssh_key,
            "target_password": target_password,
            "target_sudo": target_sudo
        }
        summary = f"Создание пользователя '{target_username}' на {len(host_ids)} серверах"
        task_type = "user_create"
    else:
        playbook_name = "user_delete.yml"
        extra_vars = {
            "target_username": target_username
        }
        summary = f"Удаление пользователя '{target_username}' с {len(host_ids)} серверов"
        task_type = "user_delete"

    task_id = dispatch_task(
        app=app,
        task_type=task_type,
        playbook_name=playbook_name,
        host_ids=host_ids,
        extra_vars=extra_vars,
        user_id=current_user.id,
        summary=summary,
        filter_info=f"Цели: {target_type}, ОС: {target_os}"
    )

    flash(f"Задача «{summary}» успешно запущена!", "success")
    return redirect(url_for("task_detail", task_id=task_id))


# -------------------------------------------------------------
# Tasks & Execution Logs
# -------------------------------------------------------------
@app.route("/tasks")
@login_required
def tasks_view():
    tasks = TaskJob.query.order_by(TaskJob.id.desc()).limit(100).all()
    return render_template("tasks.html", tasks=tasks)

@app.route("/tasks/<int:task_id>")
@login_required
def task_detail(task_id):
    task = db.get_or_404(TaskJob, task_id)
    return render_template("task_detail.html", task=task)

@app.route("/api/tasks/<int:task_id>")
@login_required
def api_task_status(task_id):
    task = db.get_or_404(TaskJob, task_id)
    return jsonify({
        "id": task.id,
        "status": task.status,
        "target_count": task.target_count,
        "success_count": task.success_count,
        "failed_count": task.failed_count,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None
    })


# -------------------------------------------------------------
# SSH Credential Profiles (Admin only)
# -------------------------------------------------------------
@app.route("/credentials")
@login_required
@admin_required
def credentials_view():
    profiles = CredentialProfile.query.order_by(CredentialProfile.os_type, CredentialProfile.name).all()
    return render_template("credentials.html", profiles=profiles)

@app.route("/credentials/create", methods=["POST"])
@login_required
@admin_required
def create_credential():
    from task_engine import normalize_private_key, validate_ssh_key

    name = request.form.get("name", "").strip()
    os_type = request.form.get("os_type", "linux")
    ssh_user = request.form.get("ssh_user", "").strip()
    ssh_port = int(request.form.get("ssh_port", 22))
    become_method = request.form.get("become_method", "sudo")
    raw_key = request.form.get("private_key", "").strip()
    private_key = normalize_private_key(raw_key)
    passphrase = request.form.get("passphrase", "").strip()
    password = request.form.get("password", "").strip()
    sudo_password = request.form.get("sudo_password", "").strip()
    is_default = request.form.get("is_default") == "1"

    if private_key:
        is_valid, err_msg = validate_ssh_key(private_key, passphrase)
        if not is_valid:
            flash(f"Ошибка в SSH-ключе: {err_msg}", "danger")
            return redirect(url_for("credentials_view"))

    if is_default:
        # Reset existing defaults for this OS
        CredentialProfile.query.filter_by(os_type=os_type, is_default=True).update({"is_default": False})

    profile = CredentialProfile(
        name=name,
        os_type=os_type,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        become_method=become_method,
        is_default=is_default
    )
    if private_key:
        profile.private_key = private_key
        profile.auth_type = "key"
        if passphrase:
            profile.passphrase = passphrase
    elif password:
        profile.password = password
        profile.auth_type = "password"

    if sudo_password:
        profile.sudo_password = sudo_password

    db.session.add(profile)
    db.session.commit()
    flash(f"Профиль «{name}» успешно создан.", "success")
    return redirect(url_for("credentials_view"))

@app.route("/credentials/<int:profile_id>/edit", methods=["POST"])
@login_required
@admin_required
def edit_credential(profile_id):
    from task_engine import normalize_private_key, validate_ssh_key

    profile = db.get_or_404(CredentialProfile, profile_id)

    name = request.form.get("name", "").strip()
    os_type = request.form.get("os_type", profile.os_type)
    ssh_user = request.form.get("ssh_user", "").strip()
    ssh_port = int(request.form.get("ssh_port", 22))
    become_method = request.form.get("become_method", "sudo")
    raw_key = request.form.get("private_key", "").strip()
    private_key = normalize_private_key(raw_key)
    passphrase = request.form.get("passphrase", "").strip()
    password = request.form.get("password", "").strip()
    sudo_password = request.form.get("sudo_password", "").strip()
    is_default = request.form.get("is_default") == "1"

    if private_key:
        eff_passphrase = passphrase if passphrase else (profile.passphrase or "")
        is_valid, err_msg = validate_ssh_key(private_key, eff_passphrase)
        if not is_valid:
            flash(f"Ошибка в SSH-ключе: {err_msg}", "danger")
            return redirect(url_for("credentials_view"))
    elif passphrase and not clear_key and profile.private_key:
        is_valid, err_msg = validate_ssh_key(profile.private_key, passphrase)
        if not is_valid:
            flash(f"Ошибка в парольной фразе: {err_msg}", "danger")
            return redirect(url_for("credentials_view"))

    if name:
        profile.name = name
    profile.os_type = os_type
    if ssh_user:
        profile.ssh_user = ssh_user
    profile.ssh_port = ssh_port
    profile.become_method = become_method

    clear_key = request.form.get("clear_key") == "1"
    if clear_key:
        profile.encrypted_private_key = None
        profile.encrypted_passphrase = None
        profile.auth_type = "password"
    elif private_key:
        profile.private_key = private_key
        profile.auth_type = "key"

    if passphrase and not clear_key:
        profile.passphrase = passphrase

    if password:
        profile.password = password
        if clear_key or (not private_key and not profile.private_key):
            profile.auth_type = "password"

    if sudo_password:
        profile.sudo_password = sudo_password

    if is_default:
        CredentialProfile.query.filter(
            CredentialProfile.id != profile.id,
            CredentialProfile.os_type == profile.os_type
        ).update({"is_default": False})
    profile.is_default = is_default

    db.session.commit()
    flash(f"Профиль «{profile.name}» успешно обновлен.", "success")
    return redirect(url_for("credentials_view"))

@app.route("/credentials/<int:profile_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_credential(profile_id):
    profile = db.get_or_404(CredentialProfile, profile_id)
    db.session.delete(profile)
    db.session.commit()
    flash(f"Профиль «{profile.name}» удален.", "info")
    return redirect(url_for("credentials_view"))


# -------------------------------------------------------------
# Zabbix Settings & Synchronization
# -------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings_view():
    setting = ZabbixSetting.query.first()
    if not setting:
        setting = ZabbixSetting()
        db.session.add(setting)
        db.session.commit()

    if request.method == "POST":
        setting.url = request.form.get("url", "").strip()
        token = request.form.get("token", "").strip()
        if token:
            setting.token = token
        setting.verify_ssl = request.form.get("verify_ssl") == "1"
        setting.auto_sync = request.form.get("auto_sync") == "1"
        setting.sync_interval_mins = int(request.form.get("sync_interval_mins", 60))
        
        # Reschedule job if interval changed
        try:
            scheduler.reschedule_job('zabbix_sync_job', trigger='interval', minutes=setting.sync_interval_mins)
        except Exception:
            pass

        db.session.commit()
        flash("Настройки Zabbix API успешно сохранены.", "success")
        return redirect(url_for("settings_view"))

    return render_template("settings.html", setting=setting)

@app.route("/settings/test-zabbix", methods=["POST"])
@login_required
@admin_required
def test_zabbix_api():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    token = data.get("token", "").strip()
    verify_ssl = bool(data.get("verify_ssl", False))

    if not token:
        setting = ZabbixSetting.query.first()
        if setting and setting.token:
            token = setting.token

    client = ZabbixClient(url, token, verify_ssl=verify_ssl)
    success, msg = client.test_connection()
    return jsonify({"success": success, "message": msg})

@app.route("/sync-zabbix", methods=["POST"])
@login_required
def sync_zabbix_now():
    setting = ZabbixSetting.query.first()
    if not setting or not setting.url or not setting.token:
        flash("Zabbix API не настроен. Перейдите в раздел «Настройки» и укажите URL и токен.", "warning")
        return redirect(url_for("settings_view"))

    success, msg, stats = sync_zabbix_to_db(db.session, setting, user_id=current_user.id)
    if success:
        flash(msg, "success")
    else:
        flash(msg, "danger")
    return redirect(url_for("hosts_view"))


# -------------------------------------------------------------
# Panel Users Management (Admin only)
# -------------------------------------------------------------
@app.route("/users")
@login_required
@admin_required
def users_view():
    users = User.query.order_by(User.id).all()
    return render_template("users_admin.html", users=users)

@app.route("/users/create", methods=["POST"])
@login_required
@admin_required
def create_panel_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "operator")

    if not username or not password:
        flash("Имя пользователя и пароль обязательны.", "danger")
        return redirect(url_for("users_view"))

    if User.query.filter_by(username=username).first():
        flash(f"Пользователь с именем «{username}» уже существует.", "danger")
        return redirect(url_for("users_view"))

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    flash(f"Пользователь «{username}» успешно создан.", "success")
    return redirect(url_for("users_view"))

@app.route("/users/reset-password", methods=["POST"])
@login_required
@admin_required
def reset_user_password():
    user_id = request.form.get("user_id")
    new_password = request.form.get("new_password", "").strip()
    if not user_id or not new_password:
        flash("Некорректные параметры сброса пароля.", "danger")
        return redirect(url_for("users_view"))

    user = db.get_or_404(User, int(user_id))
    user.set_password(new_password)
    db.session.commit()

    flash(f"Пароль для пользователя «{user.username}» успешно обновлен.", "success")
    return redirect(url_for("users_view"))

@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_panel_user(user_id):
    if user_id == current_user.id:
        flash("Вы не можете удалить свою собственную учетную запись.", "danger")
        return redirect(url_for("users_view"))

    user = db.get_or_404(User, user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Пользователь «{user.username}» удален.", "info")
    return redirect(url_for("users_view"))


# -------------------------------------------------------------
# Database initialization & default bootstrap
# -------------------------------------------------------------
def bootstrap_database():
    with app.app_context():
        db.create_all()

        # Schema auto-migration for SQLite to safely add newly added columns
        try:
            inspector = db.inspect(db.engine)
            if "hosts" in inspector.get_table_names():
                existing_cols = {col["name"] for col in inspector.get_columns("hosts")}
                with db.engine.connect() as conn:
                    if "is_ip_manually_set" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN is_ip_manually_set BOOLEAN DEFAULT 0"))
                    if "ip_source" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN ip_source VARCHAR(30) DEFAULT 'zabbix'"))
                    if "zabbix_agent_ip" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN zabbix_agent_ip VARCHAR(100) DEFAULT ''"))
                    if "zabbix_description" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN zabbix_description TEXT DEFAULT ''"))
                    if "proxy_hostid" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN proxy_hostid VARCHAR(50) DEFAULT '0'"))
                    if "ssh_port" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN ssh_port INTEGER DEFAULT NULL"))
                    if "is_os_manually_set" not in existing_cols:
                        conn.execute(db.text("ALTER TABLE hosts ADD COLUMN is_os_manually_set BOOLEAN DEFAULT 0"))
                    conn.commit()
        except Exception as e:
            print(f"[BOOTSTRAP] Migration notice: {e}")

        # 1. Create Default Admin if no users exist
        if User.query.count() == 0:
            admin = User(username="admin", role="admin")
            admin.set_password("admin")
            db.session.add(admin)
            print("[BOOTSTRAP] Created default admin user (admin / admin)")

        # 2. Create Default Zabbix Setting if not exists
        # 2. Create Default Zabbix Setting if not exists
        if ZabbixSetting.query.count() == 0:
            setting = ZabbixSetting(
                url="http://zabbix-server/api_jsonrpc.php",
                verify_ssl=False,
                auto_sync=False
            )
            db.session.add(setting)

        db.session.commit()

# Run bootstrap on module load
bootstrap_database()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
