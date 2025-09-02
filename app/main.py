from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct

# Importa a camada de persistência/infra
from .database import Base, engine, SessionLocal
from .models import User, AccessLog, Resource
from .schemas import (
    # Schemas/Pydantic usados como contratos de entrada/saída
    UserCreate, UserUpdate, UserOut, UserListOut,
    Token, LoginRequest, AccessLogOut,
    ResourceCreate, ResourceUpdate, ResourceOut, ResourceListOut,
)
from .auth import (
    # Funções utilitárias de autenticação/autorização
    get_db,               # Dependency para obter sessão do banco
    get_password_hash,    # Hash de senha
    verify_password,      # Verifica senha
    create_access_token,  # Cria JWT
    get_current_user,     # Dependency: valida o JWT e retorna o usuário atual
    require_roles,        # Dependency: exige papéis específicos
)
from .roles import Role, AREA_PERMISSIONS, can_access
# Role: enum de papéis; AREA_PERMISSIONS: mapa de permissões por área
# can_access: função que valida se um certo role pode acessar uma área


# Instancia a aplicação FastAPI
app = FastAPI(title="Sistema de Gerenciamento de Segurança")

# Configuração de CORS para permitir chamadas do frontend rodando localmente
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(\[::1\]|localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cria automaticamente as tabelas no banco ao subir a app (somente para dev)
Base.metadata.create_all(bind=engine)


@app.on_event("startup")
def ensure_admin_user():
    """
    Ao iniciar a aplicação, garante que exista um usuário 'admin' padrão.
    OBS: Apenas para ambiente de desenvolvimento. Em produção, prefira migrações/seed controlado.
    """
    db = SessionLocal()
    try:
        exists = db.query(User).filter(User.username == "admin").first()
        if not exists:
            admin = User(
                username="admin",
                password_hash=get_password_hash("admin123"),  # senha padrão (trocar após o primeiro login)
                role=Role.SECURITY_ADMIN.value,               # papel: administrador de segurança
            )
            db.add(admin)
            db.commit()
            print("[seed] Usuário admin criado: admin / admin123 (altere assim que possível)")
    finally:
        db.close()


@app.get("/")
def root():
    """
    Rota raiz com informações básicas e links úteis.
    Não exige autenticação.
    """
    return {
        "app": "Sistema de Gerenciamento de Segurança",
        "status": "ok",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/healthz",
    }

@app.get("/healthz")
def healthz():
    """Endpoint de saúde para probes/monitoramento."""
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


# ---------------------------
#           AUTH
# ---------------------------

@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Efetua login com username/password.
    - Busca usuário por username
    - Verifica senha
    - Emite JWT com 'sub' (username) e 'role'
    """
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/register", response_model=UserOut)
def register_user(
    new_user: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),  # Somente SECURITY_ADMIN pode cadastrar usuários
):
    """
    Registra um novo usuário.
    - Valida duplicidade de username
    - Aplica hash na senha
    - Define role informado
    """
    exists = db.query(User).filter(User.username == new_user.username).first()
    if exists:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    user = User(
        username=new_user.username.strip(),
        password_hash=get_password_hash(new_user.password),
        role=new_user.role.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/logout")
def logout(_: User = Depends(get_current_user)):
    """
    'Logout' sem estado do lado do servidor.
    O cliente deve descartar o token (não há blacklist/refresh aqui).
    """
    return {"message": "Logout efetuado (remova o token no cliente)."}


# ---------------------------
#        USERS (CRUD)
# ---------------------------

@app.get("/users/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    """Retorna o usuário autenticado atual (dados do token)."""
    return user

@app.get("/users", response_model=UserListOut)
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),  # Apenas admin de segurança lista todos
    q: Optional[str] = None,                       # Busca por username (ilike)
    role: Optional[Role] = Query(default=None),    # Filtro por role
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    sort: str = Query(default="username"),         # username | -username | id | -id
):
    """
    Lista usuários com paginação, filtro e ordenação.
    Retorna total, page, size e items.
    """
    qset = db.query(User)

    # Filtro de busca textual
    if q:
        like = f"%{q}%"
        qset = qset.filter(User.username.ilike(like))

    # Filtro por papel (Role)
    if role is not None:
        qset = qset.filter(User.role == role.value)

    total = qset.count()  # total antes de aplicar página/limite

    # Mapa de ordenação seguro
    sort_map = {
        "username": User.username.asc(),
        "-username": User.username.desc(),
        "id": User.id.asc(),
        "-id": User.id.desc(),
    }
    qset = qset.order_by(sort_map.get(sort, User.username.asc()))

    # Paginação
    offset = (page - 1) * size
    items = qset.offset(offset).limit(size).all()

    return {"total": total, "page": page, "size": size, "items": items}

@app.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    """Busca um usuário pelo ID. Somente SECURITY_ADMIN pode consultar arbitrariamente."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user

@app.put("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    """
    Atualiza dados de um usuário:
    - username (validando duplicidade)
    - password (re-hash)
    - role
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    # Atualiza username com verificação de duplicidade
    if payload.username is not None:
        new_username = payload.username.strip()
        if new_username != user.username:
            exists = db.query(User).filter(User.username == new_username).first()
            if exists:
                raise HTTPException(status_code=400, detail="Já existe um usuário com este username")
            user.username = new_username

    # Atualiza senha (fazendo hash)
    if payload.password is not None:
        user.password_hash = get_password_hash(payload.password)

    # Atualiza role
    if payload.role is not None:
        user.role = payload.role.value

    db.commit()
    db.refresh(user)
    return user

@app.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    """Remove um usuário por ID. Retorna 204 (sem conteúdo) em caso de sucesso."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    db.delete(user)
    db.commit()
    return None


# ---------------------------
#           ÁREAS
# ---------------------------

@app.get("/areas/allowed", response_model=List[str])
def list_my_allowed_areas(user: User = Depends(get_current_user)):
    """
    Lista as áreas permitidas para o usuário atual.
    - SECURITY_ADMIN recebe '*', representando acesso total.
    - Demais papéis consultam o mapa AREA_PERMISSIONS.
    """
    role_obj = Role(user.role)
    if role_obj == Role.SECURITY_ADMIN:
        return ["*"]
    return sorted(list(AREA_PERMISSIONS.get(role_obj, set())))

@app.post("/areas/{area}/enter", response_model=AccessLogOut)
def enter_area(area: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Registra tentativa de entrada em uma 'área'.
    - Loga sempre a tentativa (allowed True/False)
    - Se não autorizado, levanta 403 com a razão
    """
    role_obj = Role(user.role)
    allowed = can_access(role_obj, area)  # checa permissões
    reason = None if allowed else f"Acesso negado: {role_obj} não tem permissão para {area}"

    # Persiste log de acesso com timestamp UTC
    log = AccessLog(user_id=user.id, area=area, timestamp=datetime.utcnow(), allowed=allowed, reason=reason)
    db.add(log)
    db.commit()
    db.refresh(log)

    if not allowed:
        # Responde com 403, mas o log já foi gravado acima
        raise HTTPException(status_code=403, detail=reason)
    return log


# ---------------------------
#            LOGS
# ---------------------------

@app.get("/logs", response_model=List[AccessLogOut])
def list_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),  # Apenas admin de segurança
    user_id: Optional[int] = None,
    area: Optional[str] = None,
    allowed: Optional[bool] = None,
    limit: int = 100,
):
    """
    Lista logs de acesso com filtros opcionais (user_id, area, allowed).
    Ordena por timestamp desc e limita (máx. 500).
    """
    q = db.query(AccessLog)
    if user_id is not None:
        q = q.filter(AccessLog.user_id == user_id)
    if area is not None:
        q = q.filter(AccessLog.area == area)
    if allowed is not None:
        q = q.filter(AccessLog.allowed == allowed)

    q = q.order_by(AccessLog.timestamp.desc()).limit(min(limit, 500))
    return q.all()

@app.put("/logs/{log_id}", response_model=AccessLogOut)
def update_log(
    log_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
    reason: Optional[str] = Body(default=None),
    area: Optional[str] = Body(default=None),
    allowed: Optional[bool] = Body(default=None),
):
    """
    Atualiza campos de um log específico (reason, area, allowed).
    Útil para correções administrativas.
    """
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

@app.delete("/logs/{log_id}", status_code=204)
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    """Exclui um log por ID."""
    log = db.query(AccessLog).filter(AccessLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log não encontrado")
    db.delete(log)
    db.commit()
    return None

@app.delete("/logs", status_code=204)
def delete_all_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN)),
):
    """Exclui TODOS os logs. Operação destrutiva; restrita a SECURITY_ADMIN."""
    db.query(AccessLog).delete()
    db.commit()
    return None


# ---------------------------
#        RESOURCES (CRUD)
# ---------------------------

@app.get("/resources", response_model=ResourceListOut)
def list_resources(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),  # Qualquer usuário autenticado pode listar
    q: Optional[str] = None,
    category: Optional[str] = None,
    location: Optional[str] = None,
    min_qty: Optional[int] = Query(default=None, ge=0),
    max_qty: Optional[int] = Query(default=None, ge=0),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    sort: str = Query(default="name"),
):
    """
    Lista recursos com filtros (texto, categoria, local, faixa de quantidade),
    ordenação e paginação. Retorna total, page, size e items.
    """
    qset = db.query(Resource)

    # Filtro por texto em name/description (ilike)
    if q:
        like = f"%{q}%"
        qset = qset.filter((Resource.name.ilike(like)) | (Resource.description.ilike(like)))

    # Filtros exatos
    if category:
        qset = qset.filter(Resource.category == category)
    if location:
        qset = qset.filter(Resource.location == location)

    # Faixa de quantidade
    if min_qty is not None:
        qset = qset.filter(Resource.quantity >= min_qty)
    if max_qty is not None:
        qset = qset.filter(Resource.quantity <= max_qty)

    total = qset.count()

    # Ordenação segura por chaves conhecidas
    sort_map = {
        "name": Resource.name.asc(),
        "-name": Resource.name.desc(),
        "quantity": Resource.quantity.asc(),
        "-quantity": Resource.quantity.desc(),
        "created_at": Resource.created_at.asc(),
        "-created_at": Resource.created_at.desc(),
    }
    qset = qset.order_by(sort_map.get(sort, Resource.name.asc()))

    # Paginação
    offset = (page - 1) * size
    items = qset.offset(offset).limit(size).all()

    return {"total": total, "page": page, "size": size, "items": items}

@app.get("/resources/{resource_id}", response_model=ResourceOut)
def get_resource(resource_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Retorna um recurso por ID (autenticado)."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Recurso não encontrado")
    return resource

@app.post("/resources", response_model=ResourceOut, status_code=201)
def create_resource(
    payload: ResourceCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),  # Admin e Manager podem criar
):
    """
    Cria um novo recurso.
    - Normaliza strings (strip)
    - Define timestamps created_at/updated_at
    """
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

@app.put("/resources/{resource_id}", response_model=ResourceOut)
def update_resource(
    resource_id: int,
    payload: ResourceUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),  # Admin e Manager podem editar
):
    """
    Atualiza campos de um recurso (parcialmente).
    - Mantém updated_at com timestamp atual
    """
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

@app.delete("/resources/{resource_id}", status_code=204)
def delete_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.SECURITY_ADMIN, Role.MANAGER)),  # Admin e Manager podem excluir
):
    """Exclui um recurso por ID."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Recurso não encontrado")
    db.delete(resource)
    db.commit()
    return None


# ---------------------------
#           STATS
# ---------------------------

@app.get("/stats/overview")
def stats_overview(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),  # Qualquer autenticado pode ver o overview
):
    """
    KPIs simples do sistema:
    - acessos de hoje
    - usuários ativos nas últimas 24h
    - totais de recursos e usuários
    """
    now = datetime.utcnow()
    start_of_day = datetime(now.year, now.month, now.day)  # 00:00:00 UTC do dia atual

    # Total de acessos desde o início do dia
    accesses_today = (
        db.query(func.count(AccessLog.id))
        .filter(AccessLog.timestamp >= start_of_day)
        .scalar()
        or 0
    )
    # Usuários distintos que tiveram logs nas últimas 24h
    active_users_24h = (
        db.query(func.count(distinct(AccessLog.user_id)))
        .filter(AccessLog.timestamp >= now - timedelta(hours=24))
        .scalar()
        or 0
    )
    total_resources = db.query(func.count(Resource.id)).scalar() or 0
    total_users = db.query(func.count(User.id)).scalar() or 0

    return {
        "accesses_today": accesses_today,
        "active_users_24h": active_users_24h,
        "total_resources": total_resources,
        "total_users": total_users,
        "time": now.isoformat() + "Z",
    }


# ---------------------------
#       UTIL (DEV ONLY)
# ---------------------------

@app.delete("/dev/reset", status_code=204)
def reset_all(db: Session = Depends(get_db)):
    """
    Limpa TUDO (Users, Resources, AccessLogs) e recria o admin padrão.
    - Uso recomendado APENAS em desenvolvimento.
    - Não exige autenticação aqui (poderia exigir em cenários reais).
    """
    db.query(AccessLog).delete()
    db.query(Resource).delete()
    db.query(User).delete()
    db.commit()

    admin = User(
        username="admin",
        password_hash=get_password_hash("admin123"),
        role=Role.SECURITY_ADMIN.value,
    )
    db.add(admin)
    db.commit()
    return None