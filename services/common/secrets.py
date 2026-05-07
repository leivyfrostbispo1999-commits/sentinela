import os
from pathlib import Path


DEFAULT_SECRET_SENTINELS = {
    "SENTINELA_JWT_SECRET": "sentinela-demo-jwt-secret",
    "GRAFANA_ADMIN_PASSWORD": "sentinela",
}


def _read_secret_file(path):
    if not path:
        return None
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def resolve_secret(name, default=None, required=False, env=None, secrets_dir="/run/secrets"):
    env = env or os.environ
    sentinela_env = env.get("SENTINELA_ENV", "development").strip().lower()
    value = env.get(name)
    if value:
        if sentinela_env == "production" and value == DEFAULT_SECRET_SENTINELS.get(name):
            raise RuntimeError(f"{name} nao pode usar valor padrao em producao")
        return value

    file_value = _read_secret_file(env.get(f"{name}_FILE"))
    if file_value:
        return file_value

    docker_secret = _read_secret_file(Path(secrets_dir) / name)
    if docker_secret:
        return docker_secret

    if sentinela_env == "development" and default is not None:
        return default

    if required:
        raise RuntimeError(f"{name} deve ser configurado")
    return None
