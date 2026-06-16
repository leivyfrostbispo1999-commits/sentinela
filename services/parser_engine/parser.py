import hashlib
import json
import re
import socket
from datetime import datetime, timezone


EVENT_SCHEMA_VERSION = "sentinela.event.v3"

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SSH_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>[^\s]+) from (?P<src>[0-9.]+)", re.I)
SSH_ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>[^\s]+) from (?P<src>[0-9.]+)", re.I)
SUDO_RE = re.compile(r"sudo: +(?P<user>[^\s:]+).*COMMAND=(?P<command>.*)$", re.I)
NGINX_RE = re.compile(r"^(?P<src>[0-9.]+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] \"(?P<method>[A-Z]+) (?P<path>\S+)")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def stable_id(*parts):
    digest = hashlib.sha256("|".join(str(part or "") for part in parts).encode("utf-8")).hexdigest()
    return digest[:32]


def normalize_severity(value):
    severity = str(value or "").upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return severity
    return "LOW"


def raw_message(record):
    if isinstance(record, str):
        return record
    if not isinstance(record, dict):
        return str(record)
    for key in ("log", "message", "MESSAGE", "msg"):
        if record.get(key):
            return str(record[key])
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def parse_timestamp(record):
    if isinstance(record, dict):
        for key in ("timestamp", "@timestamp", "time", "date"):
            value = record.get(key)
            if value:
                return str(value)
    return utc_now()


def source_name(record):
    if not isinstance(record, dict):
        return "unknown"
    path = str(record.get("path") or record.get("logfile") or record.get("source") or "").lower()
    unit = str(record.get("_SYSTEMD_UNIT") or record.get("systemd_unit") or "").lower()
    container = str(record.get("container_name") or record.get("container_id") or "").lower()
    if "auth.log" in path or "sshd" in unit:
        return "auth"
    if "syslog" in path:
        return "syslog"
    if "nginx" in path or "nginx" in container:
        return "nginx"
    if container:
        return "docker"
    return record.get("source") or "linux"


def classify_event(message, source):
    text = message.lower()
    tags = [source]
    event_type = "LINUX_LOG"
    severity = "LOW"
    service = source
    technique = ""

    if "failed password" in text or "authentication failure" in text:
        event_type = "FAILED_LOGIN"
        severity = "MEDIUM"
        service = "ssh"
        technique = "T1110"
        tags += ["ssh", "auth_failure"]
    elif "accepted " in text and (" for " in text or " ssh2" in text):
        event_type = "LOGIN_SUCCESS"
        service = "ssh"
        tags += ["ssh", "auth_success"]
    elif "sudo:" in text:
        event_type = "SUDO_COMMAND"
        severity = "MEDIUM" if any(item in text for item in ("su ", "passwd", "chmod", "chown", "visudo", "curl", "wget")) else "LOW"
        service = "sudo"
        technique = "T1548"
        tags += ["sudo", "privilege_escalation"]
    elif any(item in text for item in ("bash -i", "/dev/tcp/", "nc -e", "ncat -e", "mkfifo")):
        event_type = "REVERSE_SHELL"
        severity = "HIGH"
        technique = "T1059"
        tags += ["reverse_shell", "command_execution"]
    elif any(item in text for item in ("curl ", "wget ", "Invoke-WebRequest".lower())):
        event_type = "SUSPICIOUS_DOWNLOAD"
        severity = "MEDIUM"
        technique = "T1105"
        tags += ["curl_wget", "ingress_tool_transfer"]
    elif any(item in text for item in ("crontab", "/etc/rc.local", "systemctl enable", ".bashrc", "authorized_keys")):
        event_type = "PERSISTENCE_INDICATOR"
        severity = "HIGH"
        technique = "T1053"
        tags += ["persistence"]
    elif source == "nginx":
        event_type = "HTTP_REQUEST"
        service = "nginx"
        tags += ["http"]
    elif source == "docker":
        event_type = "CONTAINER_LOG"
        service = "docker"
        tags += ["container"]
    elif "port scan" in text or "nmap" in text:
        event_type = "PORT_SCAN"
        severity = "HIGH"
        technique = "T1046"
        tags += ["scan"]

    return event_type, severity, service, technique, sorted(set(tags))


def extract_fields(message, event_type):
    username = ""
    source_ip = ""
    destination_ip = ""
    command = ""

    match = SSH_FAILED_RE.search(message) or SSH_ACCEPTED_RE.search(message)
    if match:
        username = match.group("user")
        source_ip = match.group("src")

    sudo = SUDO_RE.search(message)
    if sudo:
        username = username or sudo.group("user")
        command = sudo.group("command").strip()

    nginx = NGINX_RE.search(message)
    if nginx:
        source_ip = source_ip or nginx.group("src")
        username = username if username and username != "-" else (nginx.group("user") if nginx.group("user") != "-" else "")

    ips = IP_RE.findall(message)
    if not source_ip and ips:
        source_ip = ips[0]
    if len(ips) > 1:
        destination_ip = ips[1]

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "command": command,
    }


def normalize_record(record, default_host=None):
    message = raw_message(record)
    source = source_name(record)
    event_type, severity, service, technique, tags = classify_event(message, source)
    fields = extract_fields(message, event_type)
    host = ""
    if isinstance(record, dict):
        host = record.get("host") or record.get("hostname") or record.get("_HOSTNAME") or record.get("container_name") or ""
    host = host or default_host or socket.gethostname()
    timestamp = parse_timestamp(record)
    event_id = stable_id(timestamp, host, source, message)

    return {
        "event_id": event_id,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "timestamp": timestamp,
        "host": host,
        "source_ip": fields["source_ip"],
        "destination_ip": fields["destination_ip"],
        "event_type": event_type,
        "severity": normalize_severity(severity),
        "username": fields["username"],
        "raw_log": message,
        "tags": tags,
        "technique": technique,
        "service": service,
        "parser_source": source,
        "command": fields["command"],
    }
