import os
import json
import re
from datetime import datetime
from functools import wraps
import yaml
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

# Load environment variables
load_dotenv()

from models import (
    db, User, StaffMember, ZabbixSetting, CredentialProfile, 
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

# Safety policy: protected system accounts that can NEVER be deleted
PROTECTED_USERNAMES = {"ansible", "root", "admin", "administrator", "system"}



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
# Staff / Employees Directory
# -------------------------------------------------------------
@app.route("/staff", endpoint="staff_view")
@app.route("/staff", endpoint="staff_list")
@login_required
def staff_view():
    staff = StaffMember.query.order_by(StaffMember.name).all()
    return render_template("staff.html", staff=staff)

@app.route("/staff/create", methods=["POST"])
@login_required
@admin_required
def create_staff():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    department = request.form.get("department", "").strip()
    password = request.form.get("password", "").strip()
    ssh_public_key = request.form.get("ssh_public_key", "").strip()
    sudo_enabled = request.form.get("sudo_enabled") == "1"
    is_active = request.form.get("is_active") == "1"

    if not name or not username:
        flash("ФИО и системный логин обязательны для заполнения.", "danger")
        return redirect(url_for("staff_view"))

    existing = StaffMember.query.filter_by(username=username).first()
    if existing:
        flash(f"Сотрудник с логином '{username}' уже существует.", "danger")
        return redirect(url_for("staff_view"))

    staff = StaffMember(
        name=name,
        username=username,
        department=department,
        ssh_public_key=ssh_public_key,
        sudo_enabled=sudo_enabled,
        is_active=is_active
    )
    if password:
        staff.password = password

    db.session.add(staff)
    db.session.commit()
    flash(f"Сотрудник «{name}» ({username}) успешно добавлен в каталог.", "success")
    return redirect(url_for("staff_view"))

@app.route("/staff/<int:staff_id>/edit", methods=["POST"])
@login_required
@admin_required
def edit_staff(staff_id):
    staff = db.get_or_404(StaffMember, staff_id)
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip().lower()
    department = request.form.get("department", "").strip()
    password = request.form.get("password", "").strip()
    ssh_public_key = request.form.get("ssh_public_key", "").strip()
    sudo_enabled = request.form.get("sudo_enabled") == "1"
    is_active = request.form.get("is_active") == "1"

    if staff.is_system:
        # Cannot change username or disable sudo for protected system account
        username = staff.username
        sudo_enabled = True

    if username and username != staff.username:
        existing = StaffMember.query.filter_by(username=username).first()
        if existing:
            flash(f"Логин '{username}' уже занят другим сотрудником.", "danger")
            return redirect(url_for("staff_view"))
        staff.username = username

    if name:
        staff.name = name
    staff.department = department
    staff.ssh_public_key = ssh_public_key
    staff.sudo_enabled = sudo_enabled
    staff.is_active = is_active
    if password:
        staff.password = password

    db.session.commit()
    flash(f"Данные сотрудника «{staff.name}» успешно обновлены.", "success")
    return redirect(url_for("staff_view"))

@app.route("/staff/<int:staff_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_staff(staff_id):
    staff = db.get_or_404(StaffMember, staff_id)
    if staff.is_system or staff.username.lower() in PROTECTED_USERNAMES:
        flash(f"Служебный системный аккаунт «{staff.username}» защищен от удаления политикой безопасности!", "danger")
        return redirect(url_for("staff_view"))

    name = staff.name
    db.session.delete(staff)
    db.session.commit()
    flash(f"Сотрудник «{name}» удален из каталога.", "info")
    return redirect(url_for("staff_view"))


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
    staff_members = StaffMember.query.filter_by(is_active=True).order_by(StaffMember.name).all()
    selected_staff_ids = request.args.getlist("staff_ids")
    if not selected_staff_ids and request.args.get("staff_ids"):
        selected_staff_ids = [request.args.get("staff_ids")]

    if request.args.get("init_ansible") == "1":
        ansible_staff = StaffMember.query.filter_by(username="ansible").first()
        if ansible_staff:
            selected_staff_ids = [str(ansible_staff.id)]

    credential_profiles = CredentialProfile.query.order_by(CredentialProfile.os_type, CredentialProfile.is_default.desc(), CredentialProfile.name).all()

    return render_template(
        "user_ops.html",
        groups=groups,
        all_hosts_count=all_hosts_count,
        selected_host_ids=selected_host_ids,
        selected_group_id=request.args.get("group_id", ""),
        staff_members=staff_members,
        selected_staff_ids=selected_staff_ids,
        credential_profiles=credential_profiles
    )

@app.route("/user-ops/run", methods=["POST"])
@login_required
def run_user_ops():
    operation = request.form.get("operation", "create") # 'create' or 'delete'
    target_type = request.form.get("target_type", "all") # 'all', 'group', 'preselected'
    target_os = request.form.get("target_os", "all") # 'all', 'linux', 'windows'
    source_mode = request.form.get("source_mode", "catalog") # 'catalog' or 'manual'

    target_users = []

    if source_mode == "catalog":
        staff_ids = request.form.getlist("staff_ids")
        if not staff_ids:
            flash("Пожалуйста, выберите хотя бы одного сотрудника из списка.", "danger")
            return redirect(url_for("user_ops_view"))

        int_ids = [int(i) for i in staff_ids if str(i).isdigit()]
        staff_list = StaffMember.query.filter(StaffMember.id.in_(int_ids)).all()
        for s in staff_list:
            target_users.append({
                "username": s.username,
                "name": s.name,
                "ssh_key": s.ssh_public_key or "",
                "password": s.password or "",
                "sudo": bool(s.sudo_enabled)
            })
    else:
        target_username = request.form.get("target_username", "").strip()
        if not target_username:
            flash("Имя пользователя обязательно для заполнения.", "danger")
            return redirect(url_for("user_ops_view"))
        target_ssh_key = request.form.get("target_ssh_key", "").strip()
        target_password = request.form.get("target_password", "").strip()
        target_sudo = request.form.get("target_sudo") == "1"

        target_users.append({
            "username": target_username,
            "name": target_username,
            "ssh_key": target_ssh_key,
            "password": target_password,
            "sudo": target_sudo
        })

    if not target_users:
        flash("Список пользователей пуст.", "danger")
        return redirect(url_for("user_ops_view"))

    if operation == "delete":
        for u in target_users:
            if u["username"].lower() in PROTECTED_USERNAMES:
                flash(f"КРИТИЧЕСКАЯ ЗАЩИТА: Пользователь '{u['username']}' является защищенным системным аккаунтом и НЕ МОЖЕТ быть удален с серверов!", "danger")
                return redirect(url_for("user_ops_view"))

    # Determine target hosts
    query = Host.query.filter_by(is_enabled=True)

    if target_type == "preselected":
        ids_list = []
        # Source 1: form getlist for 'host_ids' or 'selected_host_ids'
        for val in request.form.getlist("host_ids") + request.form.getlist("selected_host_ids"):
            if str(val).isdigit():
                ids_list.append(int(val))

        # Source 2: JSON format from 'selected_host_ids_json'
        ids_json = request.form.get("selected_host_ids_json", "").strip()
        if ids_json:
            try:
                parsed = json.loads(ids_json)
                if isinstance(parsed, list):
                    for i in parsed:
                        if str(i).isdigit():
                            ids_list.append(int(i))
            except Exception:
                # Fallback if quotes were stripped/mangled in HTML
                cleaned = ids_json.replace("[", "").replace("]", "").replace('"', '').replace("'", "")
                for chunk in cleaned.split(","):
                    chunk = chunk.strip()
                    if chunk.isdigit():
                        ids_list.append(int(chunk))

        # Source 3: CSV format from 'selected_host_ids_csv'
        ids_csv = request.form.get("selected_host_ids_csv", "").strip()
        if ids_csv:
            for part in ids_csv.split(","):
                part = part.strip()
                if part.isdigit():
                    ids_list.append(int(part))

        # Deduplicate while preserving order
        ids_list = list(dict.fromkeys(ids_list))

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
    usernames_preview = ", ".join([u["username"] for u in target_users[:3]])
    if len(target_users) > 3:
        usernames_preview += f" и еще {len(target_users) - 3}"

    if operation == "create":
        playbook_name = "user_create.yml"
        extra_vars = {
            "target_users": target_users,
            "target_username": target_users[0]["username"],
            "target_ssh_key": target_users[0]["ssh_key"],
            "target_password": target_users[0]["password"],
            "target_sudo": target_users[0]["sudo"]
        }
        summary = f"Создание доступа для [{usernames_preview}] ({len(target_users)} чел.) на {len(host_ids)} серверах"
        task_type = "user_create"
    else:
        playbook_name = "user_delete.yml"
        extra_vars = {
            "target_users": target_users,
            "target_username": target_users[0]["username"]
        }
        summary = f"Отзыв доступа / удаление [{usernames_preview}] ({len(target_users)} чел.) с {len(host_ids)} серверов"
        task_type = "user_delete"

    cred_profile_id = request.form.get("credential_profile_id")
    if cred_profile_id and cred_profile_id.isdigit():
        extra_vars["_credential_profile_id"] = int(cred_profile_id)

    task_id = dispatch_task(
        app=app,
        task_type=task_type,
        playbook_name=playbook_name,
        host_ids=host_ids,
        extra_vars=extra_vars,
        user_id=current_user.id,
        summary=summary,
        filter_info=f"Цели: {target_type}, ОС: {target_os}, Пользователи: {len(target_users)}"
    )

    flash(f"Задача «{summary}» успешно запущена!", "success")
    return redirect(url_for("task_detail", task_id=task_id))



# -------------------------------------------------------------
# Playbooks & Automation Catalog
# -------------------------------------------------------------
PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "playbooks")
SYSTEM_PLAYBOOKS = {"ping_check.yml", "user_create.yml", "user_delete.yml"}


def get_playbook_meta(filename: str):
    playbook_path = os.path.join(PLAYBOOKS_DIR, filename)
    is_system = filename in SYSTEM_PLAYBOOKS
    meta = {
        "filename": filename,
        "is_system": is_system,
        "title": filename,
        "description": "",
        "tasks_count": 0,
        "size_kb": 0.0,
        "modified_str": "-",
        "icon": "fa-solid fa-scroll",
        "icon_bg": "bg-slate-800 text-slate-300",
    }
    if not os.path.exists(playbook_path):
        return meta

    try:
        st = os.stat(playbook_path)
        meta["size_kb"] = round(st.st_size / 1024.0, 1)
        meta["modified_str"] = datetime.fromtimestamp(st.st_mtime).strftime("%d.%m.%Y %H:%M")
    except Exception:
        pass

    try:
        with open(playbook_path, "r", encoding="utf-8") as f:
            content = f.read()
        data = yaml.safe_load(content)
        if isinstance(data, list) and len(data) > 0:
            first_play = data[0] if isinstance(data[0], dict) else {}
            play_name = first_play.get("name")
            if play_name:
                meta["title"] = play_name
            total_tasks = 0
            for play in data:
                if isinstance(play, dict) and "tasks" in play and isinstance(play["tasks"], list):
                    total_tasks += len(play["tasks"])
            meta["tasks_count"] = total_tasks
    except Exception:
        pass

    fn = filename.lower()
    if fn == "ping_check.yml":
        meta["title"] = "Быстрая проверка доступности SSH"
        meta["description"] = "Экспресс-тест SSH подключения ко всем серверам без выполнения тяжелых модулей."
        meta["icon"] = "fa-solid fa-bolt"
        meta["icon_bg"] = "bg-emerald-500/10 text-emerald-400"
    elif fn == "user_create.yml":
        meta["title"] = "Создание учетных записей & SSH-ключей"
        meta["description"] = "Массовое создание системных пользователей, настройка sudo и открытых SSH-ключей."
        meta["icon"] = "fa-solid fa-user-plus"
        meta["icon_bg"] = "bg-purple-500/10 text-purple-400"
    elif fn == "user_delete.yml":
        meta["title"] = "Отзыв доступа & удаление пользователей"
        meta["description"] = "Завершение процессов пользователя, удаление домашних каталогов и sudo-прав."
        meta["icon"] = "fa-solid fa-user-minus"
        meta["icon_bg"] = "bg-red-500/10 text-red-400"
    elif "system_update" in fn:
        meta["title"] = meta["title"] if meta["title"] != filename else "Безопасное обновление пакетов ОС"
        meta["description"] = "Обновление репозиториев и пакетов безопасности (apt-get / yum / dnf / apk)."
        meta["icon"] = "fa-solid fa-arrows-rotate"
        meta["icon_bg"] = "bg-sky-500/10 text-sky-400"
    elif "service_restart" in fn:
        meta["title"] = meta["title"] if meta["title"] != filename else "Управление системной службой systemd"
        meta["description"] = "Перезапуск, перезагрузка конфигурации, запуск или остановка любого сервиса."
        meta["icon"] = "fa-solid fa-gears"
        meta["icon_bg"] = "bg-amber-500/10 text-amber-400"
    elif "disk_space" in fn or "audit" in fn:
        meta["title"] = meta["title"] if meta["title"] != filename else "Экспресс-аудит дисков и ресурсов"
        meta["description"] = "Сбор информации об использовании диска (df -h), оперативной памяти и uptime."
        meta["icon"] = "fa-solid fa-hard-drive"
        meta["icon_bg"] = "bg-teal-500/10 text-teal-400"
    elif "docker" in fn:
        meta["title"] = meta["title"] if meta["title"] != filename else "Очистка и обслуживание Docker"
        meta["description"] = "Удаление остановленных контейнеров, неиспользуемых сетей и висячих образов."
        meta["icon"] = "fa-brands fa-docker"
        meta["icon_bg"] = "bg-blue-500/10 text-blue-400"
    else:
        if not meta.get("description"):
            meta["description"] = "Пользовательский сценарий Ansible для управления серверами."
        meta["icon"] = "fa-solid fa-file-code"
        meta["icon_bg"] = "bg-indigo-500/10 text-indigo-400"

    return meta


@app.route("/playbooks")
@login_required
def playbooks_view():
    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    all_files = [
        f for f in os.listdir(PLAYBOOKS_DIR) 
        if (f.endswith(".yml") or f.endswith(".yaml")) and os.path.isfile(os.path.join(PLAYBOOKS_DIR, f))
    ]
    all_files.sort(key=lambda name: (0 if name in SYSTEM_PLAYBOOKS else 1, name.lower()))
    playbooks = [get_playbook_meta(f) for f in all_files]
    return render_template("playbooks.html", playbooks=playbooks)


@app.route("/playbooks/new")
@login_required
def playbook_new():
    sample_content = """---
- name: Custom Automation Playbook
  hosts: all
  gather_facts: false
  become: true

  tasks:
    - name: Test connectivity & Echo
      ansible.builtin.debug:
        msg: "Running task on host: {{ inventory_hostname }}"
"""
    return render_template(
        "playbook_edit.html",
        is_new=True,
        is_system=False,
        filename="custom_task.yml",
        content=sample_content
    )


@app.route("/playbooks/<path:filename>/edit")
@login_required
def playbook_edit(filename):
    clean_filename = os.path.basename(filename)
    file_path = os.path.join(PLAYBOOKS_DIR, clean_filename)
    if not os.path.exists(file_path):
        flash(f"Плейбук «{clean_filename}» не найден.", "danger")
        return redirect(url_for("playbooks_view"))
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    is_system = clean_filename in SYSTEM_PLAYBOOKS
    return render_template(
        "playbook_edit.html",
        is_new=False,
        is_system=is_system,
        filename=clean_filename,
        content=content
    )


@app.route("/playbooks/save", methods=["POST"])
@login_required
def playbook_save():
    is_new = request.form.get("is_new") == "true"
    orig_filename = os.path.basename(request.form.get("original_filename", "").strip())
    filename = os.path.basename(request.form.get("filename", "").strip())
    content = request.form.get("content", "")

    if not filename.endswith(".yml") and not filename.endswith(".yaml"):
        filename += ".yml"

    if not re.match(r"^[a-zA-Z0-9_\-\.]+\.(yml|yaml)$", filename):
        flash("Некорректное имя файла. Разрешены только латинские буквы, цифры, дефис, подчеркивание и расширение .yml", "danger")
        return redirect(request.referrer or url_for("playbooks_view"))

    if not is_new and orig_filename in SYSTEM_PLAYBOOKS and filename != orig_filename:
        flash("Имя системного плейбука не может быть изменено!", "danger")
        return redirect(url_for("playbook_edit", filename=orig_filename))

    try:
        yaml.safe_load(content)
    except Exception as e:
        flash(f"Ошибка синтаксиса YAML: {e}", "danger")
        return render_template(
            "playbook_edit.html",
            is_new=is_new,
            is_system=(filename in SYSTEM_PLAYBOOKS),
            filename=filename,
            content=content
        )

    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    target_path = os.path.join(PLAYBOOKS_DIR, filename)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)

    audit = AuditLog(
        user_id=current_user.id,
        action="PLAYBOOK_SAVE",
        target=filename,
        description=f"{'Создан' if is_new else 'Отредактирован'} плейбук {filename}"
    )
    db.session.add(audit)
    db.session.commit()

    flash(f"Плейбук «{filename}» успешно сохранен!", "success")
    return redirect(url_for("playbooks_view"))


@app.route("/playbooks/<path:filename>/delete", methods=["POST"])
@login_required
def playbook_delete(filename):
    clean_filename = os.path.basename(filename)
    if clean_filename in SYSTEM_PLAYBOOKS:
        flash(f"Плейбук «{clean_filename}» является системным и защищен от удаления!", "danger")
        return redirect(url_for("playbooks_view"))

    file_path = os.path.join(PLAYBOOKS_DIR, clean_filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            audit = AuditLog(
                user_id=current_user.id,
                action="PLAYBOOK_DELETE",
                target=clean_filename,
                description=f"Удален пользовательский плейбук {clean_filename}"
            )
            db.session.add(audit)
            db.session.commit()
            flash(f"Плейбук «{clean_filename}» успешно удален.", "success")
        except Exception as e:
            flash(f"Ошибка при удалении файла: {e}", "danger")
    else:
        flash(f"Файл «{clean_filename}» не найден.", "warning")

    return redirect(url_for("playbooks_view"))


@app.route("/playbooks/<path:filename>/download")
@login_required
def playbook_download(filename):
    clean_filename = os.path.basename(filename)
    return send_from_directory(PLAYBOOKS_DIR, clean_filename, as_attachment=True)


@app.route("/api/playbooks/validate", methods=["POST"])
@login_required
def api_playbook_validate():
    data = request.get_json(silent=True) or {}
    yaml_content = data.get("yaml_content", "")
    if not yaml_content.strip():
        return jsonify({"valid": False, "error": "Содержимое плейбука пустое."})
    try:
        parsed = yaml.safe_load(yaml_content)
        play_count = len(parsed) if isinstance(parsed, list) else 1
        task_count = 0
        if isinstance(parsed, list):
            for play in parsed:
                if isinstance(play, dict) and "tasks" in play and isinstance(play["tasks"], list):
                    task_count += len(play["tasks"])
        return jsonify({"valid": True, "play_count": play_count, "task_count": task_count})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/playbooks/<path:filename>/run")
@login_required
def playbook_run(filename):
    clean_filename = os.path.basename(filename)
    file_path = os.path.join(PLAYBOOKS_DIR, clean_filename)
    if not os.path.exists(file_path):
        flash(f"Плейбук «{clean_filename}» не найден.", "danger")
        return redirect(url_for("playbooks_view"))

    meta = get_playbook_meta(clean_filename)
    all_hosts = Host.query.order_by(Host.name.asc()).all()
    groups = HostGroup.query.order_by(HostGroup.name.asc()).all()
    credential_profiles = CredentialProfile.query.order_by(CredentialProfile.os_type, CredentialProfile.is_default.desc(), CredentialProfile.name).all()

    return render_template(
        "playbook_run.html",
        filename=clean_filename,
        is_system=meta["is_system"],
        playbook_title=meta["title"],
        playbook_description=meta["description"],
        tasks_count=meta["tasks_count"],
        all_hosts=all_hosts,
        groups=groups,
        credential_profiles=credential_profiles
    )


@app.route("/playbooks/<path:filename>/run", methods=["POST"], endpoint="playbook_run_post")
@login_required
def playbook_run_post(filename):
    clean_filename = os.path.basename(filename)
    file_path = os.path.join(PLAYBOOKS_DIR, clean_filename)
    if not os.path.exists(file_path):
        flash(f"Плейбук «{clean_filename}» не найден.", "danger")
        return redirect(url_for("playbooks_view"))

    target_type = request.form.get("target_type", "all")
    target_os = request.form.get("target_os", "linux")
    extra_vars_raw = request.form.get("extra_vars_json", "").strip()

    extra_vars = {}
    if extra_vars_raw:
        try:
            extra_vars = json.loads(extra_vars_raw)
            if not isinstance(extra_vars, dict):
                extra_vars = {"data": extra_vars}
        except Exception:
            try:
                loaded = yaml.safe_load(extra_vars_raw)
                if isinstance(loaded, dict):
                    extra_vars = loaded
            except Exception as e:
                flash(f"Ошибка в формате дополнительных переменных: {e}", "danger")
                return redirect(url_for("playbook_run", filename=clean_filename))

    cred_profile_id = request.form.get("credential_profile_id")
    if cred_profile_id and cred_profile_id.isdigit():
        extra_vars["_credential_profile_id"] = int(cred_profile_id)

    query = Host.query
    if target_type == "preselected":
        selected_ids = request.form.getlist("selected_hosts")
        if not selected_ids:
            flash("Не выбрано ни одного сервера для запуска.", "danger")
            return redirect(url_for("playbook_run", filename=clean_filename))
        try:
            int_ids = [int(i) for i in selected_ids if str(i).isdigit()]
        except Exception:
            int_ids = []
        if not int_ids:
            flash("Список выбранных серверов пуст.", "danger")
            return redirect(url_for("playbook_run", filename=clean_filename))
        query = query.filter(Host.id.in_(int_ids))
    elif target_type == "group":
        group_id = request.form.get("group_id")
        if not group_id:
            flash("Не выбрана целевая группа.", "danger")
            return redirect(url_for("playbook_run", filename=clean_filename))
        query = query.filter_by(group_id=int(group_id))

    if target_os in ("linux", "windows"):
        query = query.filter_by(os_type=target_os)

    target_hosts = query.all()
    if not target_hosts:
        flash("Не найдено серверов, соответствующих критериям фильтрации.", "warning")
        return redirect(url_for("playbook_run", filename=clean_filename))

    host_ids = [h.id for h in target_hosts]
    meta = get_playbook_meta(clean_filename)
    summary = f"Сценарий «{meta['title']}» ({clean_filename}) на {len(host_ids)} серверах"

    task_id = dispatch_task(
        app=app,
        task_type="playbook_run",
        playbook_name=clean_filename,
        host_ids=host_ids,
        extra_vars=extra_vars,
        user_id=current_user.id,
        summary=summary,
        filter_info=f"Сценарий: {clean_filename}, Цели: {target_type}, ОС: {target_os}"
    )

    flash(f"Задача «{summary}» успешно поставлена в очередь и выполняется!", "success")
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
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
        "log_output": task.log_output or ""
    })

@app.route("/tasks/<int:task_id>/cancel", methods=["POST"])
@login_required
def cancel_task_view(task_id):
    from task_engine import cancel_task
    task = db.get_or_404(TaskJob, task_id)
    if task.status in ("running", "pending"):
        cancel_task(task.id)
        task.status = "canceled"
        task.finished_at = datetime.utcnow()
        task.log_output = (task.log_output or "") + "\n\n[ЗАДАЧА ПРЕРВАНА ПОЛЬЗОВАТЕЛЕМ]\n"
        db.session.commit()
        flash(f"Задача #{task.id} прервана.", "warning")
    return redirect(url_for("task_detail", task_id=task_id))


def get_failed_hosts_for_task(task):
    """Return list of Host objects that failed or were unreachable in this task."""
    failed_names = set()
    if task.details:
        for name, res in task.details.items():
            if isinstance(res, dict) and res.get("status") != "ok":
                failed_names.add(name)

    if not failed_names and task.log_output:
        for line in task.log_output.splitlines():
            m = re.match(r'^\s*([^\s:]+)\s*:\s*.*(?:unreachable=[1-9]|failed=[1-9])', line)
            if m:
                failed_names.add(m.group(1))
            m_fatal = re.search(r'(?:fatal|unreachable):\s*\[([^\]]+)\]', line)
            if m_fatal:
                failed_names.add(m_fatal.group(1))

    if not failed_names:
        return []

    return Host.query.filter(Host.name.in_(list(failed_names))).all()


@app.route("/tasks/<int:task_id>/retry-failed", methods=["POST"])
@login_required
def task_retry_failed(task_id):
    task = db.get_or_404(TaskJob, task_id)
    failed_hosts = get_failed_hosts_for_task(task)
    if not failed_hosts:
        flash("Не удалось автоматически определить список хостов с ошибками.", "warning")
        return redirect(url_for("task_detail", task_id=task.id))

    host_ids = [h.id for h in failed_hosts]

    playbook_name = "ping_check.yml"
    extra_vars = {}
    task_type = task.task_type

    meta_parsed = {}
    try:
        if task.filter_info and task.filter_info.strip().startswith("{"):
            meta_parsed = json.loads(task.filter_info)
    except Exception:
        pass

    if meta_parsed.get("playbook_name"):
        playbook_name = meta_parsed["playbook_name"]
        extra_vars = meta_parsed.get("extra_vars", {})
    elif task_type == "user_create":
        playbook_name = "user_create.yml"
        ansible_staff = StaffMember.query.filter_by(username="ansible").first()
        target_users = []
        if ansible_staff:
            target_users.append({
                "username": ansible_staff.username,
                "name": ansible_staff.name,
                "ssh_key": ansible_staff.ssh_public_key or "",
                "password": ansible_staff.password or "",
                "sudo": ansible_staff.sudo_enabled
            })
        extra_vars = {
            "target_users": target_users,
            "target_username": target_users[0]["username"] if target_users else "ansible",
            "target_ssh_key": target_users[0]["ssh_key"] if target_users else "",
            "target_password": target_users[0]["password"] if target_users else "",
            "target_sudo": target_users[0]["sudo"] if target_users else True
        }
    elif task_type == "user_delete":
        playbook_name = "user_delete.yml"
        extra_vars = {"target_users": [{"username": "ansible"}]}
    elif task_type == "ping":
        playbook_name = "ping_check.yml"
    elif task_type == "playbook_run":
        m = re.search(r'\(([^)]+\.(?:yml|yaml))\)', task.summary or "")
        playbook_name = m.group(1) if m else "system_update.yml"

    new_task_id = dispatch_task(
        app=app,
        task_type=task_type,
        playbook_name=playbook_name,
        host_ids=host_ids,
        extra_vars=extra_vars,
        user_id=current_user.id,
        summary=f"[ПОВТОР ОШИБОК #{task.id}] {task.summary}",
        filter_info=f"Повтор для {len(host_ids)} ошибочных серверов из задачи #{task.id}"
    )

    flash(f"Запущен повтор задачи на {len(host_ids)} хостах с ошибками!", "success")
    return redirect(url_for("task_detail", task_id=new_task_id))


@app.route("/tasks/<int:task_id>/open-failed-in-user-ops", methods=["POST"])
@login_required
def task_open_failed_in_user_ops(task_id):
    task = db.get_or_404(TaskJob, task_id)
    failed_hosts = get_failed_hosts_for_task(task)
    if not failed_hosts:
        flash("Не найдено хостов с ошибками.", "warning")
        return redirect(url_for("task_detail", task_id=task.id))

    selected_host_ids = [str(h.id) for h in failed_hosts]
    groups = HostGroup.query.order_by(HostGroup.name).all()
    all_hosts_count = Host.query.filter_by(is_enabled=True).count()
    staff_members = StaffMember.query.filter_by(is_active=True).order_by(StaffMember.name).all()
    ansible_staff = StaffMember.query.filter_by(username="ansible").first()
    selected_staff_ids = [str(ansible_staff.id)] if ansible_staff else []

    return render_template(
        "user_ops.html",
        groups=groups,
        all_hosts_count=all_hosts_count,
        selected_host_ids=selected_host_ids,
        selected_group_id="",
        staff_members=staff_members,
        selected_staff_ids=selected_staff_ids
    )




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
    clear_key = request.form.get("clear_key") == "1"

    if not clear_key and private_key:
        eff_passphrase = passphrase if passphrase else (profile.passphrase or "")
        is_valid, err_msg = validate_ssh_key(private_key, eff_passphrase)
        if not is_valid:
            flash(f"Ошибка в SSH-ключе: {err_msg}", "danger")
            return redirect(url_for("credentials_view"))
    elif not clear_key and passphrase and profile.private_key:
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


@app.route("/credentials/<int:profile_id>/set-default", methods=["POST"])
@login_required
@admin_required
def set_default_credential(profile_id):
    profile = db.get_or_404(CredentialProfile, profile_id)
    CredentialProfile.query.filter_by(os_type=profile.os_type, is_default=True).update({"is_default": False})
    profile.is_default = True
    db.session.commit()
    flash(f"Профиль «{profile.name}» (пользователь: {profile.ssh_user}) назначен профилем по умолчанию для {profile.os_type.upper()}.", "success")
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

@app.errorhandler(500)
def handle_internal_server_error(e):
    import traceback
    tb = traceback.format_exc()
    return f"""
    <div style="background:#0f172a;color:#e2e8f0;padding:24px;font-family:monospace;border-radius:12px;margin:20px;border:1px solid #334155">
        <h2 style="color:#ef4444;margin-top:0">Internal Server Error (500)</h2>
        <p style="color:#94a3b8">При обработке запроса произошла ошибка:</p>
        <pre style="background:#020617;color:#fca5a5;padding:16px;border-radius:8px;overflow-x:auto;border:1px solid #1e293b">{tb}</pre>
    </div>
    """, 500


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

            if "staff_members" in inspector.get_table_names():
                staff_cols = {col["name"] for col in inspector.get_columns("staff_members")}
                with db.engine.connect() as conn:
                    if "is_system" not in staff_cols:
                        conn.execute(db.text("ALTER TABLE staff_members ADD COLUMN is_system BOOLEAN DEFAULT 0"))
                    conn.commit()
        except Exception as e:
            print(f"[BOOTSTRAP] Migration notice: {e}")

        # 1. Ensure protected 'ansible' system service account exists in Staff catalog
        try:
            ansible_staff = StaffMember.query.filter_by(username="ansible").first()
            if not ansible_staff:
                ansible_staff = StaffMember(
                    name="Служебная автоматизация Ansible",
                    username="ansible",
                    department="DevOps / Automation",
                    sudo_enabled=True,
                    is_system=True,
                    is_active=True
                )
                db.session.add(ansible_staff)
                db.session.commit()
                print("[BOOTSTRAP] Created protected 'ansible' system account in Staff catalog.")
        except Exception as e:
            db.session.rollback()
            print(f"[BOOTSTRAP] Staff check notice: {e}")

        # 2. Create Default Admin if no users exist
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
