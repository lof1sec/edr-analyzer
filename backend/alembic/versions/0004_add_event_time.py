"""add log_events.event_time

Revision ID: 0004_add_event_time
Revises: 0003_add_graph_layouts
Create Date: 2026-10-05

Normalised event time (epoch milliseconds) used by the chronological timeline.
Nullable, so events without a usable timestamp keep insertion order. Written
defensively (like the earlier revisions) so it is a no-op if the column already
exists.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0004_add_event_time"
down_revision = "0003_add_graph_layouts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "log_events" not in set(inspector.get_table_names()):
        return

    columns = {column["name"] for column in inspector.get_columns("log_events")}
    if "event_time" in columns:
        return

    op.add_column("log_events", sa.Column("event_time", sa.BigInteger(), nullable=True))
    op.create_index(
        op.f("ix_log_events_event_time"),
        "log_events",
        ["event_time"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_log_events_event_time"), table_name="log_events")
    op.drop_column("log_events", "event_time")
