"""Add schedule tables

Revision ID: a1b2c3d4e5f7
Revises: b2c3d4e5f6a7
Create Date: 2026-02-21 17:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from open_webui.migrations.util import get_existing_tables

revision: str = "a1b2c3d4e5f7"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    existing_tables = set(get_existing_tables())

    if "schedule" not in existing_tables:
        op.create_table(
            "schedule",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("user_id", sa.String()),
            sa.Column("name", sa.Text()),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("model_id", sa.String()),
            sa.Column("prompt", sa.Text()),
            sa.Column("tools", sa.Text(), nullable=True),
            sa.Column("filters", sa.Text(), nullable=True),
            sa.Column("frequency", sa.String()),
            sa.Column("scheduled_at", sa.BigInteger(), nullable=True),
            sa.Column("is_active", sa.Boolean(), default=True),
            sa.Column("meta", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.BigInteger()),
            sa.Column("created_at", sa.BigInteger()),
            sa.PrimaryKeyConstraint("id"),
        )
    else:
        # Add columns that may be missing from earlier versions of this table
        inspector = sa.inspect(op.get_bind())
        existing_columns = {col["name"] for col in inspector.get_columns("schedule")}
        if "filters" not in existing_columns:
            op.add_column("schedule", sa.Column("filters", sa.Text(), nullable=True))

    if "schedule_run" not in existing_tables:
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


def downgrade() -> None:
    op.drop_table("schedule_run")
    op.drop_table("schedule")
