# ============================================================
# schemas.py — Modelos Pydantic (contratos de entrada/saída)
# Comentado em português, em uma única página.
# ============================================================

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from .roles import Role  # Enum de papéis (EMPLOYEE, MANAGER, SECURITY_ADMIN, etc.)

# ------------------------------------------------------------
# 👤 USERS — criação, atualização e respostas de usuário
# ------------------------------------------------------------

class UserCreate(BaseModel):
    # Payload para criar usuário novo (usado em POST /auth/register)
    username: str = Field(min_length=3, max_length=50)      # login (validado por tamanho)
    password: str = Field(min_length=6, max_length=128)     # senha em texto (hash será feito no backend)
    role: Role                                              # papel (enum definido em roles.py)

class UserUpdate(BaseModel):
    # Payload para atualizar usuário (parcial) — usado em PUT /users/{id}
    username: Optional[str] = Field(default=None, min_length=3, max_length=50)
    password: Optional[str] = Field(default=None, min_length=6, max_length=128)
    role: Optional[Role] = None                             # pode trocar o papel

class UserOut(BaseModel):
    # Modelo de saída (nunca inclui senha) — usado em responses
    id: int
    username: str
    role: Role

    class Config:
        from_attributes = True  # permite criar a partir de objetos ORM (SQLAlchemy)

class UserListOut(BaseModel):
    # Envelope de paginação para listagem de usuários — usado em GET /users
    total: int                   # total de registros encontrados
    page: int                    # página atual
    size: int                    # tamanho da página
    items: List[UserOut]         # lista de usuários (cada item é UserOut)

# ------------------------------------------------------------
# 🔐 AUTH — login e token
# ------------------------------------------------------------

class Token(BaseModel):
    # Resposta do login — usado em POST /auth/login
    access_token: str            # JWT emitido pelo backend
    token_type: str = "bearer"   # tipo padrão para Authorization: Bearer <token>

class LoginRequest(BaseModel):
    # Payload do login — usado em POST /auth/login
    username: str
    password: str

# ------------------------------------------------------------
# 📜 AREAS / LOGS — leitura de logs de acesso
# ------------------------------------------------------------

class AccessLogOut(BaseModel):
    # Modelo de saída para um log de acesso — usado em GET /logs e POST /areas/{area}/enter
    id: int                      # id do log
    user_id: int                 # id do usuário que tentou acessar
    area: str                    # nome da área
    timestamp: datetime          # quando ocorreu (UTC)
    allowed: bool                # se o acesso foi permitido
    reason: Optional[str]        # motivo da negativa (quando allowed=False), opcional

    class Config:
        from_attributes = True   # compatível com objetos ORM

# ------------------------------------------------------------
# 📦 RESOURCES — CRUD de recursos
# ------------------------------------------------------------

class ResourceBase(BaseModel):
    # Campos comuns a criação/atualização/retorno de recursos
    name: str = Field(min_length=2, max_length=120)         # nome do recurso
    category: str = Field(min_length=2, max_length=60)      # categoria (ex.: Equipamentos)
    quantity: int = Field(ge=0)                             # quantidade (não negativa)
    location: Optional[str] = Field(default=None, max_length=120)   # localização opcional
    description: Optional[str] = Field(default=None, max_length=500) # descrição opcional

class ResourceCreate(ResourceBase):
    # Payload para criar recurso (mesmos campos de ResourceBase)
    pass

class ResourceUpdate(BaseModel):
    # Payload para atualizar recurso (parcial) — usado em PUT /resources/{id}
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    category: Optional[str] = Field(default=None, min_length=2, max_length=60)
    quantity: Optional[int] = Field(default=None, ge=0)
    location: Optional[str] = Field(default=None, max_length=120)
    description: Optional[str] = Field(default=None, max_length=500)

class ResourceOut(ResourceBase):
    # Modelo de saída de um recurso — herda validações de ResourceBase
    id: int  # identificador do recurso

    class Config:
        from_attributes = True   # permite resposta direta a partir do ORM

class ResourceListOut(BaseModel):
    # Envelope de paginação para listagem de recursos — usado em GET /resources
    total: int                   # total de recursos encontrados
    page: int                    # página atual
    size: int                    # tamanho da página
    items: List[ResourceOut]     # lista de recursos (cada item é ResourceOut)