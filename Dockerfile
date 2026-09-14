FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_HOST_KEY_CHECKING=False

WORKDIR /app

# Install system dependencies, OpenSSH client, sshpass and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    curl \
    ca-certificates \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir ansible-core>=2.15.0

# Install Ansible collections for Linux and Windows SSH
RUN ansible-galaxy collection install ansible.posix community.general

# Create instance and keys storage directories
RUN mkdir -p /app/instance /app/playbooks /root/.ssh && chmod 700 /root/.ssh

COPY . .

EXPOSE 5050

CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
