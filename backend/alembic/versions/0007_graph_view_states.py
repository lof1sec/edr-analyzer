"""Store explicitly saved graph views separately from layouts.

Revision ID: 0007_graph_view_states
Revises: 0006_timeline_search_indexes
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_graph_view_states"
down_revision = "0006_timeline_search_indexes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "graph_view_states",
        sa.Column("dataset_id", sa.Integer(), sa.ForeignKey("datasets.id"), primary_key=True),
        sa.Column("state", JSONB(), nullable=False),
    )


def downgrade():
    op.drop_table("graph_view_states")
