from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from .roles import Role


# ----------------------------
# User Schemas
# ----------------------------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)
    role: Role


class UserOut(BaseModel):
    id: int
    username: str
    role: Role

    class Config:
        from_attributes = True


# ----------------------------
# Auth Schemas
# ----------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


# ----------------------------
# Área / Acesso Schemas
# ----------------------------
class EnterAreaRequest(BaseModel):
    area: str = Field(examples=["recepcao", "escritorio1", "gerencia", "sala_reuniao"])


class AccessLogOut(BaseModel):
    id: int
    user_id: int
    area: str
    timestamp: datetime
    allowed: bool
    reason: Optional[str]

    class Config:
        from_attributes = True


# ----------------------------
# Resource (Gestão de Recursos) Schemas
# ----------------------------
class ResourceBase(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=60)
    quantity: int = Field(ge=0)
    location: Optional[str] = Field(default=None, max_length=120)
    description: Optional[str] = Field(default=None, max_length=500)


class ResourceCreate(ResourceBase):
    pass


class ResourceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    category: Optional[str] = Field(default=None, min_length=2, max_length=60)
    quantity: Optional[int] = Field(default=None, ge=0)
    location: Optional[str] = Field(default=None, max_length=120)
    description: Optional[str] = Field(default=None, max_length=500)


class ResourceOut(ResourceBase):
    id: int

    class Config:
        from_attributes = True


class ResourceListOut(BaseModel):
    total: int
    page: int
    size: int
    items: List[ResourceOut]