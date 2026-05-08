"""initial sentinela schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import os

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Localiza o init.sql relativo a este arquivo de migração
    # migrations/versions/0001...py -> ../../init.sql
    base_path = os.path.dirname(os.path.abspath(__file__))
    init_sql_path = os.path.join(base_path, "..", "..", "init.sql")
    
    with open(init_sql_path, encoding="utf-8") as f:
        op.execute(f.read())


def downgrade():
    op.drop_table("incident_audit_log")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
    op.drop_table("incident_overrides")
    op.drop_table("blacklist")
    op.drop_table("alertas")
