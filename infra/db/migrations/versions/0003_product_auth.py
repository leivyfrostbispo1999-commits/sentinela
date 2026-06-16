"""product auth hardening

Revision ID: 0003_product_auth
Revises: 0002_foundation_expansion
Create Date: 2026-05-16
"""
from alembic import op

revision = "0003_product_auth"
down_revision = "0002_foundation_expansion"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slug TEXT")
    op.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS company_name TEXT")
    op.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")
    op.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS retention_days INTEGER DEFAULT 30")
    op.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_users INTEGER DEFAULT 25")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug) WHERE slug IS NOT NULL")

    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'viewer'")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default'")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ")
    op.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users (tenant_id, role)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users (locked_until)")

    op.execute("ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS user_id INTEGER")
    op.execute("ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS last_refresh_at TIMESTAMPTZ")
    op.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth_sessions (tenant_id, expires_at) WHERE revoked_at IS NULL")

    op.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_id INTEGER")
    op.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_type TEXT")
    op.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_id TEXT")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs (tenant_id, target_type, target_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS incident_events (
            id SERIAL PRIMARY KEY,
            tenant_id TEXT DEFAULT 'default',
            incident_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            correlation_id TEXT,
            source_ip TEXT,
            hostname TEXT,
            username TEXT,
            event_type TEXT,
            severity TEXT,
            score INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id SERIAL PRIMARY KEY,
            tenant_id TEXT DEFAULT 'default',
            incident_id TEXT NOT NULL,
            event_id TEXT,
            event_type TEXT NOT NULL,
            title TEXT,
            severity TEXT,
            score INTEGER DEFAULT 0,
            correlation_id TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            payload JSONB DEFAULT '{}'::jsonb
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_created_at ON incident_events (created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_correlation_id ON incident_events (correlation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_source_ip ON incident_events (source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_tenant_id ON incident_events (tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_timeline_created_at ON incident_timeline (created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_timeline_correlation_id ON incident_timeline (correlation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incident_timeline_tenant_id ON incident_timeline (tenant_id)")


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_audit_logs_target")
    op.execute("DROP TABLE IF EXISTS incident_timeline")
    op.execute("DROP TABLE IF EXISTS incident_events")
    op.execute("DROP INDEX IF EXISTS idx_auth_sessions_active")
    op.execute("DROP INDEX IF EXISTS idx_users_locked_until")
    op.execute("DROP INDEX IF EXISTS idx_users_tenant_role")
