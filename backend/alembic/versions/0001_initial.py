"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-02

Baseline schema for the EDR analyzer. Written defensively so it can be applied
to a fresh database *and* to a database whose tables were previously created by
``Base.metadata.create_all`` (which leaves no ``alembic_version``).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = set(inspect(op.get_bind()).get_table_names())

    if "datasets" not in existing:
        op.create_table(
            "datasets",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_datasets_id"), "datasets", ["id"], unique=False)
        op.create_index(op.f("ix_datasets_name"), "datasets", ["name"], unique=False)

    if "log_events" not in existing:
        op.create_table(
            "log_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("dataset_id", sa.Integer(), nullable=True),
            sa.Column("event_type", sa.String(), nullable=True),
            sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.ForeignKeyConstraint(["dataset_id"], ["datasets.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_log_events_id"), "log_events", ["id"], unique=False)
        op.create_index(
            op.f("ix_log_events_dataset_id"), "log_events", ["dataset_id"], unique=False
        )
        op.create_index(
            op.f("ix_log_events_event_type"), "log_events", ["event_type"], unique=False
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_log_events_event_type"), table_name="log_events")
    op.drop_index(op.f("ix_log_events_dataset_id"), table_name="log_events")
    op.drop_index(op.f("ix_log_events_id"), table_name="log_events")
    op.drop_table("log_events")
    op.drop_index(op.f("ix_datasets_name"), table_name="datasets")
    op.drop_index(op.f("ix_datasets_id"), table_name="datasets")
    op.drop_table("datasets")
