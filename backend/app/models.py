from datetime import datetime

from sqlalchemy import JSON, BigInteger, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    logs = relationship("LogEvent", back_populates="dataset", cascade="all, delete-orphan")

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, ForeignKey("datasets.id"), index=True)
    event_type = Column(String, index=True) # e.g. ProcessCreated, etc
    # Normalised event time (epoch milliseconds), extracted from the raw event at
    # upload. Nullable: events without a usable timestamp fall back to insertion
    # order in the timeline.
    event_time = Column(BigInteger, index=True, nullable=True)
    # JSONB on PostgreSQL (production); plain JSON elsewhere (e.g. sqlite tests).
    data = Column(JSON().with_variant(JSONB, "postgresql"))

    dataset = relationship("Dataset", back_populates="logs")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class GraphLayout(Base):
    """Saved node positions for a dataset's graph (one row per dataset).

    Kept in its own table so listing datasets never has to load the (potentially
    large) positions blob. ``positions`` is ``{node_id: {x, y}}`` and survives
    re-opening a dataset, so a user's arrangement is not lost.
    """

    __tablename__ = "graph_layouts"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(
        Integer, ForeignKey("datasets.id"), unique=True, index=True, nullable=False
    )
    positions = Column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=dict
    )
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
