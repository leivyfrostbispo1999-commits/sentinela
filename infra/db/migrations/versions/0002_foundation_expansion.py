"""foundation expansion (RBAC, Alert & Incident metadata)

Revision ID: 0002_foundation_expansion
Revises: 0001_initial_schema
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_foundation_expansion"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade():
    # RBAC Tables - Using IF NOT EXISTS via raw execute or checking before op.create_table
    op.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash TEXT NOT NULL, email VARCHAR(255) UNIQUE, is_active BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())")
    op.execute("CREATE TABLE IF NOT EXISTS roles (id SERIAL PRIMARY KEY, name VARCHAR(50) UNIQUE NOT NULL, description TEXT)")
    op.execute("CREATE TABLE IF NOT EXISTS permissions (id SERIAL PRIMARY KEY, name VARCHAR(100) UNIQUE NOT NULL, description TEXT)")
    op.execute("CREATE TABLE IF NOT EXISTS role_permissions (role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE, permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY (role_id, permission_id))")
    op.execute("CREATE TABLE IF NOT EXISTS user_roles (user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY (user_id, role_id))")

    # Expanding Alertas - Using raw SQL to avoid column exists error
    op.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS dedup_key UUID")
    op.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 3")
    op.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 100")
    op.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]'")
    op.execute("ALTER TABLE alertas ADD COLUMN IF NOT EXISTS geo_context JSONB DEFAULT '{}'")

    # Expanding Incidents
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 3")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledgment_state VARCHAR(50) DEFAULT 'unacknowledged'")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS owner VARCHAR(100)")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS attack_timeline JSONB DEFAULT '[]'")

    # Initial Roles & Permissions - Use ON CONFLICT DO NOTHING
    op.execute("INSERT INTO roles (name, description) VALUES ('super_admin', 'Full access'), ('admin', 'System administration'), ('analyst', 'SOC Analysis'), ('viewer', 'Read-only access'), ('auditor', 'Compliance & Auditing') ON CONFLICT (name) DO NOTHING")
    
    op.execute("INSERT INTO permissions (name, description) VALUES ('alert:read', 'View alerts'), ('alert:write', 'Modify alerts'), ('incident:read', 'View incidents'), ('incident:write', 'Modify incidents'), ('user:manage', 'Manage users'), ('audit:read', 'View audit logs') ON CONFLICT (name) DO NOTHING")

    # Mapping Analyst Role to permissions
    op.execute("INSERT INTO role_permissions (role_id, permission_id) SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'analyst' AND p.name IN ('alert:read', 'alert:write', 'incident:read', 'incident:write') ON CONFLICT DO NOTHING")
    op.execute("INSERT INTO role_permissions (role_id, permission_id) SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'super_admin' ON CONFLICT DO NOTHING")


def downgrade():
    op.drop_column("incidents", "attack_timeline")
    op.drop_column("incidents", "owner")
    op.drop_column("incidents", "acknowledgment_state")
    op.drop_column("incidents", "priority")

    op.drop_column("alertas", "geo_context")
    op.drop_column("alertas", "tags")
    op.drop_column("alertas", "confidence_score")
    op.drop_column("alertas", "priority")
    op.drop_column("alertas", "dedup_key")

    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")
