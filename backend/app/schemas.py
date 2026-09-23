from pydantic import BaseModel
from typing import Dict, Any, List
from datetime import datetime

class DatasetResponse(BaseModel):
    id: int
    name: str
    created_at: datetime
    log_count: int

    class Config:
        from_attributes = True

class GraphNode(BaseModel):
    data: Dict[str, Any]

class GraphEdge(BaseModel):
    data: Dict[str, Any]

class GraphResponse(BaseModel):
    elements: Dict[str, List[Any]] # contains nodes and edges
