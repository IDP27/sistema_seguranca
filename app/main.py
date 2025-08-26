from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import Base, engine, SessionLocal
from .models import User, AccessLog, Resource
from .schemas import (
    # Usuários / Auth / Áreas / Logs
    UserCreate,
    UserOut,
    Token,
    LoginRequest,
    EnterAreaRequest,
    AccessLogOut,
    # Recursos
    ResourceCreate,
    ResourceUpdate,
    ResourceOut,
    ResourceListOut,
)
from .auth import (
    get_db,
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    require_roles,
)
from .roles import Role, AREA_PERMISSIONS, can_access


app = FastAPI(title="Sistema de Gerenciamento de Segurança")

# ----- CORS (corrigido: apenas uma configuração, sem aninhar) -----
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],   # OPTIONS, GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],   # Content-Type, Authorization, etc.
)

# Cria tabelas
Base.metadata.create_all(bind=engine)

# Seed: garante um admin inicial
@app.on_event("startup")
def ensure_admin_user():
    db = SessionLocal()
    try:
        exists = db.query(User).filter(User.username == "admin").first()
        if not exists:
            admin = User(
                username="admin",
                password_hash=get_password_hash("admin123"),
                role=Role.SECURITY_ADMIN.value,
            )
            db.add(admin)
            db.commit()
            print("[seed] Usuário admin criado: admin / admin123 (altere assim que possível)")
    finally:
        db.close()


# ---------- AUTH ----------
@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/register", response_model=UserOut)
def register_user(
    new_user: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    exists = db.query(User).filter(User.username == new_user.username).first()
    if exists:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    user = User(
        username=new_user.username,
        password_hash=get_password_hash(new_user.password),
        role=new_user.role.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/logout")
def logout(_: User = Depends(get_current_user)):
    # JWT é stateless; logout do lado do cliente remove o token.
    return {"message": "Logout efetuado (apague o token no cliente)."}


# ---------- USERS ----------
@app.get("/users/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ---------- ÁREAS & PERMISSÕES ----------
@app.get("/areas/allowed", response_model=List[str])
def list_my_allowed_areas(user: User = Depends(get_current_user)):
    role = Role(user.role)
    if role == Role.SECURITY_ADMIN:
        return ["*"]
    return sorted(list(AREA_PERMISSIONS.get(role, set())))


@app.post("/areas/{area}/enter", response_model=AccessLogOut)
def enter_area(area: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    role = Role(user.role)
    allowed = can_access(role, area)

    reason = None if allowed else f"Acesso negado: {role} não tem permissão para {area}"
    log = AccessLog(user_id=user.id, area=area, timestamp=datetime.utcnow(), allowed=allowed, reason=reason)
    db.add(log)
    db.commit()
    db.refresh(log)

    if not allowed:
        raise HTTPException(status_code=403, detail=reason)

    return log


# ---------- LOGS ----------
@app.get("/logs", response_model=List[AccessLogOut])
def list_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
    user_id: Optional[int] = None,
    area: Optional[str] = None,
    allowed: Optional[bool] = None,
    limit: int = 100,
):
    q = db.query(AccessLog)
    if user_id is not None:
        q = q.filter(AccessLog.user_id == user_id)
    if area is not None:
        q = q.filter(AccessLog.area == area)
    if allowed is not None:
        q = q.filter(AccessLog.allowed == allowed)
    q = q.order_by(AccessLog.timestamp.desc()).limit(min(limit, 500))
    return q.all()


# Atualizar um log (apenas SECURITY_ADMIN)
@app.put("/logs/{log_id}", response_model=AccessLogOut)
def update_log(
    log_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
    reason: Optional[str] = Body(default=None),
    area: Optional[str] = Body(default=None),
    allowed: Optional[bool] = Body(default=None),
):
    log = db.query(AccessLog).filter(AccessLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log não encontrado")

    if reason is not None:
        log.reason = reason
    if area is not None:
        log.area = area
    if allowed is not None:
        log.allowed = allowed

    db.commit()
    db.refresh(log)
    return log


# Deletar um log específico (apenas SECURITY_ADMIN)
@app.delete("/logs/{log_id}", status_code=204)
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    log = db.query(AccessLog).filter(AccessLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log não encontrado")
    db.delete(log)
    db.commit()
    return None


# Deletar todos os logs (apenas SECURITY_ADMIN)
@app.delete("/logs", status_code=204)
def delete_all_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    db.query(AccessLog).delete()
    db.commit()
    return None


# ---------- GESTÃO DE RECURSOS ----------
# Listar com filtros/paginação (qualquer usuário autenticado)
@app.get("/resources", response_model=ResourceListOut)
def list_resources(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    q: Optional[str] = None,                  # busca por nome/descrição
    category: Optional[str] = None,
    location: Optional[str] = None,
    min_qty: Optional[int] = Query(default=None, ge=0),
    max_qty: Optional[int] = Query(default=None, ge=0),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    sort: str = Query(default="name"),        # name | -name | quantity | -quantity | created_at | -created_at
):
    qset = db.query(Resource)

    # filtros
    if q:
        like = f"%{q}%"
        qset = qset.filter((Resource.name.ilike(like)) | (Resource.description.ilike(like)))
    if category:
        qset = qset.filter(Resource.category == category)
    if location:
        qset = qset.filter(Resource.location == location)
    if min_qty is not None:
        qset = qset.filter(Resource.quantity >= min_qty)
    if max_qty is not None:
        qset = qset.filter(Resource.quantity <= max_qty)

    total = qset.count()

    # ordenação
    sort_map = {
        "name": Resource.name.asc(),
        "-name": Resource.name.desc(),
        "quantity": Resource.quantity.asc(),
        "-quantity": Resource.quantity.desc(),
        "created_at": Resource.created_at.asc(),
        "-created_at": Resource.created_at.desc(),
    }
    qset = qset.order_by(sort_map.get(sort, Resource.name.asc()))

    # paginação
    offset = (page - 1) * size
    items = qset.offset(offset).limit(size).all()

    return {
        "total": total,
        "page": page,
        "size": size,
        "items": items,
    }


# Obter um recurso por ID (qualquer autenticado)
@app.get("/resources/{resource_id}", response_model=ResourceOut)
def get_resource(resource_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Recurso não encontrado")
    return resource


# Criar recurso (ADMIN e MANAGER)
@app.post("/resources", response_model=ResourceOut, status_code=201)
def create_resource(
    payload: ResourceCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),
):
    resource = Resource(
        name=payload.name.strip(),
        category=payload.category.strip(),
        quantity=payload.quantity,
        location=(payload.location.strip() if payload.location else None),
        description=(payload.description.strip() if payload.description else None),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource


# Atualizar recurso (ADMIN e MANAGER)
@app.put("/resources/{resource_id}", response_model=ResourceOut)
def update_resource(
    resource_id: int,
    payload: ResourceUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),
):
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Recurso não encontrado")

    if payload.name is not None:
        resource.name = payload.name.strip()
    if payload.category is not None:
        resource.category = payload.category.strip()
    if payload.quantity is not None:
        resource.quantity = payload.quantity
    if payload.location is not None:
        resource.location = payload.location.strip() if payload.location else None
    if payload.description is not None:
        resource.description = payload.description.strip() if payload.description else None

    resource.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(resource)
    return resource


# Remover recurso (ADMIN e MANAGER)
@app.delete("/resources/{resource_id}", status_code=204)
def delete_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),
):
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Recurso não encontrado")
    db.delete(resource)
    db.commit()
    return None


# ---------- RESET (somente desenvolvimento) ----------
@app.delete("/dev/reset", status_code=204)
def reset_all(db: Session = Depends(get_db)):
    db.query(AccessLog).delete()
    db.query(Resource).delete()
    db.query(User).delete()
    db.commit()

    # recria o admin
    admin = User(
        username="admin",
        password_hash=get_password_hash("admin123"),
        role=Role.SECURITY_ADMIN.value,
    )
    db.add(admin)
    db.commit()
    return None