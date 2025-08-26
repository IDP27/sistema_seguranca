from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


# ----------------------------
# User
# ----------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="EMPLOYEE")

    logs = relationship("AccessLog", back_populates="user", cascade="all, delete-orphan")


# ----------------------------
# AccessLog
# ----------------------------
class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    area = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    allowed = Column(Boolean, default=False, nullable=False)
    reason = Column(String, nullable=True)

    user = relationship("User", back_populates="logs")


# ----------------------------
# Resource (Gestão de Recursos)
# ----------------------------
class Resource(Base):
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)       # nome do recurso
    category = Column(String, nullable=False, index=True)   # ex.: equipamento, veiculo, dispositivo
    quantity = Column(Integer, nullable=False, default=1)   # quantidade disponível
    location = Column(String, nullable=True, index=True)    # ex.: almoxarifado, bloco A
    description = Column(String, nullable=True)             # observações
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)