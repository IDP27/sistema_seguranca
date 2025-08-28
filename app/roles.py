from enum import Enum

class Role(str, Enum):
    EMPLOYEE = "EMPLOYEE"
    MANAGER = "MANAGER"
    SECURITY_ADMIN = "SECURITY_ADMIN"

# Áreas exemplo
AREA_PERMISSIONS = {
    Role.EMPLOYEE: {"recepcao", "escritorio1"},
    Role.MANAGER: {"recepcao", "escritorio1", "gerencia", "sala_reuniao"},
    Role.SECURITY_ADMIN: {"*"},
}

def can_access(role: Role, area: str) -> bool:
    if role == Role.SECURITY_ADMIN:
        return True
    allowed = AREA_PERMISSIONS.get(role, set())
    return area in allowed