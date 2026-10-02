from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class AuthStatus(BaseModel):
    """Tells the SPA whether to show first-run setup and if a session is active."""

    needs_setup: bool
    authenticated: bool
    username: str | None = None


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("username")
    @classmethod
    def _strip_username(cls, value: str) -> str:
        stripped = value.strip()
        if len(stripped) < 3:
            raise ValueError("username must be at least 3 characters")
        return stripped


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    created_at: datetime
