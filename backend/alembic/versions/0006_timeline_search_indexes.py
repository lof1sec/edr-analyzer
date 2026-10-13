"""Add indexes for timeline time-window and substring searches.

Revision ID: 0006_timeline_search_indexes
Revises: 0005_clear_graph_layouts

The trigram expression index is PostgreSQL-specific. Keep it in this manual
migration; SQLite tests use the portable composite index from model metadata.
"""

from alembic import op
from sqlalchemy import inspect

revision = "0006_timeline_search_indexes"
down_revision = "0005_clear_graph_layouts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "log_events" not in inspect(bind).get_table_names():
        return
    indexes = {index["name"] for index in inspect(bind).get_indexes("log_events")}
    if "ix_log_events_dataset_time_id" not in indexes:
        op.create_index(
            "ix_log_events_dataset_time_id", "log_events",
            ["dataset_id", "event_time", "id"],
        )
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_log_events_data_trgm "
            "ON log_events USING gin ((CAST(data AS text)) gin_trgm_ops)"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "log_events" not in inspect(bind).get_table_names():
        return
    if bind.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_log_events_data_trgm")
    indexes = {index["name"] for index in inspect(bind).get_indexes("log_events")}
    if "ix_log_events_dataset_time_id" in indexes:
        op.drop_index("ix_log_events_dataset_time_id", table_name="log_events")
