import pytest

from ivp.auth.roles import (
    Permission,
    PermissionDenied,
    Role,
    has_permission,
    permissions_for,
    require_permission,
)

ALL_PERMISSIONS = set(Permission)


def test_agent_permissions_are_exactly_expected():
    assert permissions_for(Role.AGENT) == {
        Permission.REQUEST_SENSITIVE_ACTION,
        Permission.VIEW_OWN_TICKETS,
    }


def test_supervisor_permissions_are_exactly_expected():
    assert permissions_for(Role.SUPERVISOR) == {
        Permission.VIEW_TEAM_TICKETS,
        Permission.VIEW_TEAM_AUDIT_LOG,
    }


def test_admin_permissions_are_exactly_expected():
    assert permissions_for(Role.ADMIN) == {
        Permission.VIEW_ALL_TICKETS,
        Permission.VIEW_ALL_AUDIT_LOG,
        Permission.MANAGE_STAFF_ACCOUNTS,
        Permission.MANAGE_ADAPTER_CONFIG,
        Permission.ADMIN_OVERRIDE_TICKET,
    }


@pytest.mark.parametrize("role", [Role.AGENT, Role.SUPERVISOR])
def test_admin_override_permission_is_exclusive_to_admin(role):
    """The RBAC decision this project makes: only admins may override
    ticket closure. This test exists specifically to catch a future PR
    that accidentally grants ADMIN_OVERRIDE_TICKET to another role."""
    assert not has_permission(role, Permission.ADMIN_OVERRIDE_TICKET)


def test_admin_override_permission_is_granted_to_admin():
    assert has_permission(Role.ADMIN, Permission.ADMIN_OVERRIDE_TICKET)


@pytest.mark.parametrize("role", list(Role))
def test_every_role_permission_set_is_disjoint_from_no_role(role):
    """No role silently falls back to a permissive default."""
    assert permissions_for(role) <= ALL_PERMISSIONS
    assert permissions_for(role)  # every real role has at least one permission


def test_require_permission_raises_for_disallowed_combination():
    with pytest.raises(PermissionDenied):
        require_permission(Role.AGENT, Permission.ADMIN_OVERRIDE_TICKET)


def test_require_permission_is_silent_for_allowed_combination():
    require_permission(Role.ADMIN, Permission.ADMIN_OVERRIDE_TICKET)  # must not raise


def test_permission_denied_carries_role_and_permission_for_audit_logging():
    with pytest.raises(PermissionDenied) as exc_info:
        require_permission(Role.SUPERVISOR, Permission.ADMIN_OVERRIDE_TICKET)
    assert exc_info.value.role == Role.SUPERVISOR
    assert exc_info.value.permission == Permission.ADMIN_OVERRIDE_TICKET


def test_no_role_can_approve_or_deny_confirmations():
    """Approval/denial belongs exclusively to the account holder via the
    enrolled channel callback — no staff permission for it should ever
    exist. This test fails loudly if that invariant is ever broken."""
    forbidden_names = {"APPROVE", "DENY", "APPROVE_CONFIRMATION", "DENY_CONFIRMATION"}
    assert not ({p.name for p in Permission} & forbidden_names)
