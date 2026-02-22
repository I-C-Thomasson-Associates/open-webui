"""Add schedule tables

Revision ID: a1b2c3d4e5f7
Revises: b2c3d4e5f6a7
Create Date: 2026-02-21 17:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f7"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "schedule",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String()),
        sa.Column("name", sa.Text()),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("model_id", sa.String()),
        sa.Column("prompt", sa.Text()),
        sa.Column("tools", sa.Text(), nullable=True),
        sa.Column("frequency", sa.String()),
        sa.Column("scheduled_at", sa.BigInteger(), nullable=True),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("meta", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.BigInteger()),
        sa.Column("created_at", sa.BigInteger()),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "schedule_run",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("schedule_id", sa.String()),
        sa.Column("status", sa.String()),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("started_at", sa.BigInteger(), nullable=True),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger()),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("schedule_run")
    op.drop_table("schedule")
