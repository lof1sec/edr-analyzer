"""add graph_layouts table

Revision ID: 0003_add_graph_layouts
Revises: 0002_add_users
Create Date: 2026-10-03

Persists the user's node arrangement per dataset (``{node_id: {x, y}}``) so
re-opening a graph restores the layout instead of re-running the force layout.
Written defensively (like the earlier revisions) so it is a no-op if the table
already exists.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0003_add_graph_layouts"
down_revision = "0002_add_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "graph_layouts" in set(inspect(op.get_bind()).get_table_names()):
        return

    op.create_table(
        "graph_layouts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("positions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["dataset_id"], ["datasets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_graph_layouts_id"), "graph_layouts", ["id"], unique=False)
    op.create_index(
        op.f("ix_graph_layouts_dataset_id"),
        "graph_layouts",
        ["dataset_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_graph_layouts_dataset_id"), table_name="graph_layouts")
    op.drop_index(op.f("ix_graph_layouts_id"), table_name="graph_layouts")
    op.drop_table("graph_layouts")
