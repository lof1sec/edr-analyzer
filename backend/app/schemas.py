from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class Position(BaseModel):
    """A saved node position (Cytoscape coordinates)."""

    x: float
    y: float


class LayoutRequest(BaseModel):
    """Persisted graph layout: node id -> position."""

    positions: dict[str, Position] = Field(default_factory=dict)


class ViewStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rangeFrom: int | None = None
    rangeTo: int | None = None
    globalSearch: str = Field(default="", max_length=4096)
    hiddenEventTypes: list[str] = Field(default_factory=list, max_length=10000)
    hiddenUsers: list[str] = Field(default_factory=list, max_length=10000)
    hiddenPids: list[str] = Field(default_factory=list, max_length=10000)
    hiddenElements: list[str] = Field(default_factory=list, max_length=100000)

    @field_validator("hiddenEventTypes", "hiddenUsers", "hiddenPids", "hiddenElements")
    @classmethod
    def validate_ids(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 8192 for value in values):
            raise ValueError("Filter values must be nonempty and at most 8192 characters")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def validate_range(self):
        if self.rangeFrom is not None and self.rangeTo is not None and self.rangeFrom > self.rangeTo:
            raise ValueError("rangeFrom must not exceed rangeTo")
        return self


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


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    created_at: datetime
