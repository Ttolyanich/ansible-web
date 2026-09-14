# 🚀 Ansible-Web & Zabbix Inventory Control

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Ansible](https://img.shields.io/badge/Ansible-2.15%2B-red.svg)](https://www.ansible.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)

Централизованная веб-панель управления инфраструктурой из 500+ серверов. Автоматически собирает хосты и группы из **Zabbix API**, проверяет их доступность по SSH с высоким параллелизмом и предоставляет единый интерфейс для создания и удаления пользователей на разнородных серверах (**Linux** от Debian 8 / CentOS 7 и **Windows Server** через OpenSSH).

---

## ⚡ Ключевые возможности

1. **Динамическая синхронизация с Zabbix API:**
   - Сбор групп хостов (компаний/департаментов) и серверов по кнопке или по расписанию (крон).
   - Автоматическое определение типа ОС по привязанным шаблонам агента (`*linux by zabbix agent*` &rarr; Linux, `*windows by zabbix agent*` &rarr; Windows) с возможностью ручной корректировки.
2. **Массовая проверка доступности (SSH Ping Check):**
   - Быстрый опрос сотен серверов за 30–60 секунд без сбора тяжелых фактов (`gather_facts: false`, `forks: 50`, `ConnectTimeout: 5s`).
   - Унифицированный транспорт: и Linux, и Windows опрашиваются по SSH.
3. **Управление учетными записями («Универсальный ключ»):**
   - **Linux:** создание системного пользователя, проброс публичного SSH-ключа в `authorized_keys`, настройка беспарольного `sudo` (`/etc/sudoers.d/username`).
   - **Windows:** создание локального пользователя с паролем, добавление в локальную группу `Administrators`, снятие срока действия пароля.
   - **Удаление:** принудительное завершение процессов пользователя (`pkill` / `net user /delete`) и корректная очистка домашнего каталога и прав `sudo`.
4. **Иерархия учетных данных подключения:**
   - Глобальные профили по умолчанию: Linux (`root` или `itsgsrv` с sudo), Windows (`ITSGSRV`).
   - Переопределение на уровне группы компании или конкретного уникального хоста.
   - Все пароли и приватные SSH-ключи зашифрованы симметричным ключом **Fernet (AES)** в локальной SQLite БД.
5. **Мультиаккаунтность и роли:**
   - **Admin:** настройка Zabbix API, управление SSH-ключами, создание пользователей панели и сброс паролей.
   - **Operator:** просмотр инвентаря, запуск проверки доступности, создание/удаление пользователей на серверах.
   - Журнал аудита действий (Audit Log).

---

## 📂 Структура проекта

```text
e:/Antigravity/ansible-web/
├── app.py                      # Веб-сервер Flask, маршруты и API
├── models.py                   # Модели БД (SQLite/SQLAlchemy) с шифрованием Fernet
├── zabbix_client.py            # Клиент Zabbix API (JSON-RPC 2.0)
├── task_engine.py              # Фоновый движок Ansible (ThreadPoolExecutor + generator inventory)
├── playbooks/
│   ├── ping_check.yml          # Плейбук быстрой проверки доступности
│   ├── user_create.yml         # Плейбук создания пользователя (Linux + Windows)
│   └── user_delete.yml         # Плейбук удаления пользователя
├── templates/                  # Jinja2 HTML шаблоны с темной темой (Tailwind)
├── static/                     # Стили и скрипты
├── Dockerfile                  # Сборка образа (Python + Ansible-core + OpenSSH)
├── docker-compose.yml          # Запуск контейнера
├── requirements.txt            # Зависимости Python
└── .env.example                # Переменные окружения
```

---

## 🚀 Быстрый запуск

### Вариант 1: Запуск через Docker Compose (Рекомендуется для продакшена)

```bash
cd /opt/ansible-web  # или путь к папке проекта
docker compose up -d --build
```
Панель будет доступна по адресу: `http://<IP_сервера>:5050`

### Вариант 2: Локальный запуск (Python)

1. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
2. Создайте файл окружения:
   ```bash
   cp .env.example .env
   ```
3. Запустите приложение:
   ```bash
   python app.py
   ```

---

## 🔑 Авторизация по умолчанию

При первом запуске автоматически создается учетная запись администратора:
- **Логин:** `admin`
- **Пароль:** `admin`

*(Рекомендуется сразу сменить пароль в разделе «Пользователи»)*

---

## 🛠️ Первоначальная настройка

1. Перейдите в **«Настройки»** (`/settings`), укажите URL вашего Zabbix сервера (например, `https://zabbix.company.com/api_jsonrpc.php`) и созданный API Token. Нажмите «Проверить подключение».
2. Нажмите **«Синхронизировать Zabbix»** в панели дашборда или в списке хостов. Все хосты и компании подтянутся в панель.
3. В разделе **«Ключи SSH»** (`/credentials`) задайте приватный SSH-ключ для профилей Linux и Windows, чтобы Ansible мог подключаться к хостам.
4. Запустите проверку доступности **«SSH Ping всех хостов»** с главного экрана!
