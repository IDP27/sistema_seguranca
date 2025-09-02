# ============================================================
# roles.py — Definição de papéis (roles) e permissões de áreas
# ============================================================

from enum import Enum

# ------------------------------------------------------------
# Enum Role: define os tipos de usuários no sistema
# ------------------------------------------------------------
class Role(str, Enum):
    EMPLOYEE = "EMPLOYEE"            # Funcionário comum
    MANAGER = "MANAGER"              # Gerente (tem mais permissões)
    SECURITY_ADMIN = "SECURITY_ADMIN" # Administrador de segurança (acesso total)


# ------------------------------------------------------------
# Dicionário de permissões por área
# ------------------------------------------------------------
# Cada role (papel) tem um conjunto de áreas que pode acessar.
# O SECURITY_ADMIN tem acesso a tudo (representado por "*").
AREA_PERMISSIONS = {
    Role.EMPLOYEE: {"recepcao", "escritorio1"},  # Funcionário pode acessar áreas básicas
    Role.MANAGER: {"recepcao", "escritorio1", "gerencia", "sala_reuniao"},  # Gerente acessa mais áreas
    Role.SECURITY_ADMIN: {"*"},  # Admin de segurança acessa qualquer área
}


# ------------------------------------------------------------
# Função utilitária para verificar acesso
# ------------------------------------------------------------
def can_access(role: Role, area: str) -> bool:
    """
    Retorna True se o papel (role) informado tiver permissão
    para acessar a área especificada.
    """
    # Admin de segurança sempre tem acesso
    if role == Role.SECURITY_ADMIN:
        return True
    
    # Busca o conjunto de áreas permitidas para o role
    allowed = AREA_PERMISSIONS.get(role, set())
    
    # Retorna True se a área solicitada está no conjunto permitido
    return area in allowed