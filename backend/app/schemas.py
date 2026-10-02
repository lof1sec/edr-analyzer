from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class DatasetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    log_count: int

class GraphNode(BaseModel):
    data: dict[str, Any]

class GraphEdge(BaseModel):
    data: dict[str, Any]

class GraphResponse(BaseModel):
    elements: dict[str, list[Any]] # contains nodes and edges
