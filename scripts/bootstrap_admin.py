import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone

import psycopg2

try:
    from passlib.context import CryptContext
except ImportError:
    CryptContext = None


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "postgres"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "root"),
}


def pbkdf2_hash(password):
    salt = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240000)
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"pbkdf2_sha256$240000${salt}${encoded}"


def hash_password(password):
    if CryptContext:
        return CryptContext(schemes=["bcrypt"], deprecated="auto").hash(password)
    return pbkdf2_hash(password)


def main():
    tenant_id = os.getenv("SENTINELA_BOOTSTRAP_TENANT", "default")
    company_name = os.getenv("SENTINELA_BOOTSTRAP_COMPANY", "Sentinela Default Tenant")
    username = os.getenv("SENTINELA_BOOTSTRAP_ADMIN", "admin")
    email = os.getenv("SENTINELA_BOOTSTRAP_EMAIL", "admin@sentinela.local")
    password = os.getenv("SENTINELA_BOOTSTRAP_PASSWORD")
    generated = False
    if not password:
        password = secrets.token_urlsafe(18) + "Aa1"
        generated = True

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (tenant_id, slug, company_name, name, plan_id, api_key, status, is_active, retention_days, max_users)
                VALUES (%s, %s, %s, %s, 'enterprise', %s, 'active', TRUE, 30, 25)
                ON CONFLICT (tenant_id) DO UPDATE
                SET company_name = EXCLUDED.company_name,
                    name = EXCLUDED.name,
                    is_active = TRUE,
                    updated_at = NOW()
                """,
                (tenant_id, tenant_id, company_name, company_name, f"{tenant_id}-bootstrap-api-key"),
            )
            cur.execute(
                """
                INSERT INTO users (
                    username, email, password_hash, role, tenant_id, is_active,
                    failed_login_attempts, locked_until, created_by, created_at, updated_at
                )
                VALUES (%s, %s, %s, 'admin', %s, TRUE, 0, NULL, 'bootstrap_admin.py', %s, %s)
                ON CONFLICT (username) DO UPDATE
                SET email = EXCLUDED.email,
                    password_hash = EXCLUDED.password_hash,
                    role = 'admin',
                    tenant_id = EXCLUDED.tenant_id,
                    is_active = TRUE,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    updated_at = NOW()
                """,
                (username, email, hash_password(password), tenant_id, datetime.now(timezone.utc), datetime.now(timezone.utc)),
            )
        conn.commit()
    finally:
        conn.close()

    print(f"bootstrap_admin=ok tenant={tenant_id} username={username}")
    if generated:
        print(f"generated_password={password}")


if __name__ == "__main__":
    main()
