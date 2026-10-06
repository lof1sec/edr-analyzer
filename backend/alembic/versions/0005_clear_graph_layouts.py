"""clear stale graph layouts after host-scoped process ids

Revision ID: 0005_clear_graph_layouts
Revises: 0004_add_event_time
Create Date: 2026-10-06

Process node ids are now host-scoped (``pid@host``) so the same PID on two
hosts no longer collapses into one node. Saved layouts key positions by node
id, so layouts written before this change reference ids that no longer exist.
Clear them once so the graph re-runs its layout cleanly instead of carrying
dead positions. Data-only and idempotent.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0005_clear_graph_layouts"
down_revision = "0004_add_event_time"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "graph_layouts" not in set(inspect(bind).get_table_names()):
        return
    op.execute(sa.text("DELETE FROM graph_layouts"))


def downgrade() -> None:
    # The deleted layouts cannot be restored; nothing to undo.
    pass
