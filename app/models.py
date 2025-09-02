# Imports do SQLAlchemy para definir colunas, tipos e relacionamentos
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
# Usaremos datetime.utcnow como default para timestamps
from datetime import datetime

# Base ORM compartilhada (declarative base) definida em database.py
from .database import Base


# ============================
# 👤 Modelo de Usuário (tabela: users)
# ============================
class User(Base):
    __tablename__ = "users"  # nome físico da tabela no banco

    # Chave primária inteira, indexada para consultas rápidas
    id = Column(Integer, primary_key=True, index=True)

    # Username único (constraint unique) e indexado (busca rápida)
    username = Column(String, unique=True, index=True, nullable=False)

    # Hash da senha (nunca armazene senha em texto plano)
    password_hash = Column(String, nullable=False)

    # Papel do usuário no sistema (ex.: EMPLOYEE, MANAGER, SECURITY_ADMIN)
    role = Column(String, nullable=False, default="EMPLOYEE")

    # Relacionamento 1:N com AccessLog
    # - back_populates conecta com o atributo "user" do AccessLog
    # - cascade="all, delete-orphan": ao deletar o User, remove seus logs
    logs = relationship(
        "AccessLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )


# ======================================
# 📜 Modelo de Log de Acesso (access_logs)
# ======================================
class AccessLog(Base):
    __tablename__ = "access_logs"

    # Chave primária e índice
    id = Column(Integer, primary_key=True, index=True)

    # FK para users.id (cada log pertence a um usuário)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Nome da área acessada (ex.: "laboratorio", "servidores")
    area = Column(String, nullable=False)

    # Momento da tentativa de acesso, default em UTC
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Se o acesso foi permitido (True) ou negado (False)
    allowed = Column(Boolean, default=False, nullable=False)

    # Motivo da negativa (opcional). Em caso de allowed=False, pode detalhar a razão
    reason = Column(String, nullable=True)

    # Relacionamento N:1 com User
    # - back_populates liga ao atributo "logs" do User
    user = relationship("User", back_populates="logs")


# =================================
# 📦 Modelo de Recurso (resources)
# =================================
class Resource(Base):
    __tablename__ = "resources"

    # Chave primária e índice
    id = Column(Integer, primary_key=True, index=True)

    # Nome do recurso (indexado para buscas textuais)
    name = Column(String, nullable=False, index=True)

    # Categoria do recurso (ex.: "Equipamentos", "Documentos"); indexada
    category = Column(String, nullable=False, index=True)

    # Quantidade disponível (inteiro, default=1)
    quantity = Column(Integer, nullable=False, default=1)

    # Localização física (opcional), indexada para filtros (ex.: "Almoxarifado A")
    location = Column(String, nullable=True, index=True)

    # Descrição detalhada (opcional)
    description = Column(String, nullable=True)

    # Timestamp de criação (UTC)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Timestamp da última atualização (UTC)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)