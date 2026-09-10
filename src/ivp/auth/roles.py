"""RBAC roles and permissions (hard requirement 9: every route enforces its
role requirement server-side via this module, never by hiding UI elements).

Pure logic, no FastAPI/session dependency, so it's testable in isolation and
reusable both by the web layer (src/ivp/auth/deps.py, added when the FastAPI
app is wired up) and directly by domain code that needs a second,
defense-in-depth check (see core.ticket.TicketClosureGate.admin_override).
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    AGENT = "AGENT"
    SUPERVISOR = "SUPERVISOR"
    ADMIN = "ADMIN"


class Permission(StrEnum):
    REQUEST_SENSITIVE_ACTION = "REQUEST_SENSITIVE_ACTION"
    VIEW_OWN_TICKETS = "VIEW_OWN_TICKETS"
    VIEW_TEAM_TICKETS = "VIEW_TEAM_TICKETS"
    VIEW_TEAM_AUDIT_LOG = "VIEW_TEAM_AUDIT_LOG"
    VIEW_ALL_TICKETS = "VIEW_ALL_TICKETS"
    VIEW_ALL_AUDIT_LOG = "VIEW_ALL_AUDIT_LOG"
    MANAGE_STAFF_ACCOUNTS = "MANAGE_STAFF_ACCOUNTS"
    MANAGE_ADAPTER_CONFIG = "MANAGE_ADAPTER_CONFIG"
    # Restricted to admin only per docs/decisions/admin-override.md —
    # supervisors do NOT get this permission.
    ADMIN_OVERRIDE_TICKET = "ADMIN_OVERRIDE_TICKET"


_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.AGENT: frozenset(
        {
            Permission.REQUEST_SENSITIVE_ACTION,
            Permission.VIEW_OWN_TICKETS,
        }
    ),
    Role.SUPERVISOR: frozenset(
        {
            Permission.VIEW_TEAM_TICKETS,
            Permission.VIEW_TEAM_AUDIT_LOG,
        }
    ),
    Role.ADMIN: frozenset(
        {
            Permission.VIEW_ALL_TICKETS,
            Permission.VIEW_ALL_AUDIT_LOG,
            Permission.MANAGE_STAFF_ACCOUNTS,
            Permission.MANAGE_ADAPTER_CONFIG,
            Permission.ADMIN_OVERRIDE_TICKET,
        }
    ),
}


class PermissionDenied(Exception):
    def __init__(self, role: Role, permission: Permission):
        self.role = role
        self.permission = permission
        super().__init__(f"role {role} lacks permission {permission}")


def permissions_for(role: Role) -> frozenset[Permission]:
    return _ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in permissions_for(role)


def require_permission(role: Role, permission: Permission) -> None:
    if not has_permission(role, permission):
        raise PermissionDenied(role, permission)
