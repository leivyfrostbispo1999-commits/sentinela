"""initial sentinela schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute(open("infra/db/init.sql", encoding="utf-8").read())


def downgrade():
    op.drop_table("incident_audit_log")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
    op.drop_table("incident_overrides")
    op.drop_table("blacklist")
    op.drop_table("alertas")
