# ============================================================
# auth.py — Autenticação (JWT), Hash de Senha e RBAC (roles)
# Comentado em português, em uma única página.
# ============================================================

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .database import SessionLocal                # fábrica de sessões do SQLAlchemy
from .models import User                          # modelo User (ORM)
from .roles import Role                           # enum de papéis (EMPLOYEE/MANAGER/SECURITY_ADMIN)

# -------------------- Configurações de JWT --------------------
# Chave secreta para assinar os tokens (use variável de ambiente em produção!)
SECRET_KEY = os.environ.get("SECRET_KEY", "devsecret-change-me")
ALGORITHM = "HS256"                               # algoritmo de assinatura do JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8              # expiração: 8 horas

# -------------------- Criptografia de senha -------------------
# Contexto do Passlib com bcrypt para hashing de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------- Esquema de autenticação -----------------
# HTTP Bearer lê o header Authorization: Bearer <token>
# auto_error=False permite tratar manualmente a ausência/invalidade do token
bearer_scheme = HTTPBearer(auto_error=False)

# -------------------- Dependency de DB ------------------------
def get_db():
    """
    Fornece uma sessão de banco (SQLAlchemy) por requisição.
    Garante fechamento apropriado via 'yield' + 'finally'.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------- Helpers de senha ------------------------
def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verifica se a senha em texto puro corresponde ao hash armazenado.
    """
    return pwd_context.verify(plain_password, password_hash)

def get_password_hash(password: str) -> str:
    """
    Gera o hash (bcrypt) a partir da senha em texto puro.
    """
    return pwd_context.hash(password)

# -------------------- Criação de JWT --------------------------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token JWT assinado contendo os 'claims' em 'data'.
    - Adiciona o 'exp' (expiração) com base em ACCESS_TOKEN_EXPIRE_MINUTES
      ou no 'expires_delta' opcional.
    - Retorna string do token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -------------------- Usuário atual (via token) ---------------
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Extrai o usuário atual a partir de um token Bearer JWT.
    - Valida presença do token (401 se ausente).
    - Decodifica e valida assinatura/expiração (401 se inválido).
    - Verifica 'sub' (username) no payload.
    - Busca usuário no banco (401 se não encontrado).
    - Retorna instância ORM de User.
    """
    # Sem credenciais → não autenticado
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = credentials.credentials
    try:
        # Decodifica o JWT e valida assinatura/exp
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")   # 'sub' = subject (aqui, o username)
        if username is None:
            # Token sem 'sub' → inválido
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        # Assinatura inválida, token expirado ou malformado
        raise HTTPException(status_code=401, detail="Invalid token")

    # Busca o usuário no banco
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# -------------------- RBAC: requisito de papéis ---------------
def require_roles(*roles: Role):
    """
    Factory de dependency que exige que o usuário autenticado
    possua **um dos** papéis informados em 'roles'.
    Uso: Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER))
    """
    def _role_dependency(user: User = Depends(get_current_user)) -> User:
        # Converte o valor armazenado no banco (string) para Role (Enum)
        try:
            user_role = Role(user.role)
        except Exception:
            # Valor inesperado/fora do Enum
            raise HTTPException(status_code=403, detail="Role inválida")

        # Verifica se o papel do usuário está permitido
        if user_role not in roles:
            raise HTTPException(status_code=403, detail="Permissões insuficientes")

        # Retorna o usuário para a rota que declarou a dependência
        return user

    return _role_dependency