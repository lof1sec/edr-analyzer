from pydantic import BaseModel, ConfigDict
from typing import Dict, Any, List
from datetime import datetime

class DatasetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    log_count: int

class GraphNode(BaseModel):
    data: Dict[str, Any]

class GraphEdge(BaseModel):
    data: Dict[str, Any]

class GraphResponse(BaseModel):
    elements: Dict[str, List[Any]] # contains nodes and edges
