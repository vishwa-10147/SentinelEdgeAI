"""Multi-tenant fleet for MSPs / MSSPs (Phase 11): customers, per-customer roles, branding, usage reports.

* A **tenant** (customer) owns groups; its sites are the sites in those groups. Existing fleets are the
  `default` tenant, so nothing changes for a single organisation.
* **Who sees what.** A console account with no tenant membership is MSP staff and sees every tenant with
  its console role. An account with memberships is scoped: it only sees the tenants it belongs to, with the
  role it has there, capped by its console role (an Operator account made `admin` of a tenant still acts as
  an Operator). Templates, federated learning and community sharing are MSP-wide: MSP staff only.
* **Branding:** display name, accent colour (#rrggbb) and a support contact per tenant, shown in the console
  and on usage reports.
* **Usage reports:** per tenant and month: sites, site-days with a report, alerts and remote actions, as
  JSON or CSV (`python -m fleet usage --month 2026-11`, `GET /api/fleet/usage`).
"""
import csv
import io
import re

from core import auth

ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,40}$')
ROLES = ('viewer', 'operator', 'admin')
COLOR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')


class TenantError(ValueError):
    pass


class Scope:
    """What one console principal may see and do on the fleet server."""

    def __init__(self, principal, st):
        self.username = principal.get('username') or ''
        self.console_role = principal.get('role') or 'viewer'
        # API tokens act for their owner, so they get the owner's customer scope too (never more)
        account = principal.get('owner') if principal.get('kind') == 'api_token' else self.username
        self.memberships = st.memberships(account) if account else {}
        self.msp = not self.memberships                  # MSP staff: every tenant, with the console role

    def role_in(self, tenant):
        if self.msp:
            return self.console_role
        role = self.memberships.get(tenant)
        if role is None:
            return None
        return min(role, self.console_role, key=auth.ROLE_RANK.get)    # capped by the console role

    def can(self, tenant, minimum):
        role = self.role_in(tenant)
        return role is not None and auth.role_allows(role, minimum)

    def tenants(self):
        """Tenant ids this principal may see (None: all)."""
        return None if self.msp else set(self.memberships)

    def require(self, tenant, minimum):
        if not self.can(tenant, minimum):
            raise PermissionError(f'needs the {minimum} role for this customer')

    def require_msp(self, minimum='admin'):
        if not (self.msp and auth.role_allows(self.console_role, minimum)):
            raise PermissionError('MSP-wide settings are for MSP staff (accounts not limited to customers)')


def create(st, tenant_id, name, by='cli'):
    if not ID_RE.match(tenant_id or ''):
        raise TenantError('tenant id: 2-41 lowercase letters, digits and dashes')
    if not name or len(name) > 80:
        raise TenantError('tenant name: 1-80 characters')
    if st.get_tenant(tenant_id):
        raise TenantError(f'tenant {tenant_id} exists')
    st.create_tenant(tenant_id, name, by)
    return st.get_tenant(tenant_id)


def brand(st, tenant_id, display_name=None, accent=None, support=None):
    t = st.get_tenant(tenant_id)
    if not t:
        raise TenantError(f'no tenant {tenant_id}')
    b = dict(t['branding'])
    if display_name is not None:
        if len(display_name) > 80:
            raise TenantError('display name: at most 80 characters')
        b['display_name'] = display_name
    if accent is not None:
        if not COLOR_RE.match(accent):
            raise TenantError('accent must be a colour like #1f6feb')
        b['accent'] = accent.lower()
    if support is not None:
        if len(support) > 120 or not re.match(r'^[^<>"\s]+@[^<>"\s]+$|^https://[^<>"\s]+$', support):
            raise TenantError('support contact: an e-mail address or an https:// link')
        b['support'] = support
    st.set_branding(tenant_id, b)
    return st.get_tenant(tenant_id)


def member(st, username, tenant_id, role):
    if role not in ROLES:
        raise TenantError(f'role must be one of {", ".join(ROLES)}')
    if not st.get_tenant(tenant_id):
        raise TenantError(f'no tenant {tenant_id}')
    if not auth.get_store().get_user(username):
        raise TenantError(f'no console account {username}')
    st.add_member(username, tenant_id, role)
    return st.memberships(username)


def assign_group(st, group, tenant_id):
    if not st.get_tenant(tenant_id):
        raise TenantError(f'no tenant {tenant_id}')
    if not st.get_group(group):
        raise TenantError(f'no group {group}')
    st.set_group_tenant(group, tenant_id)


def filter_overview(ov, scope, st):
    """The fleet overview reduced to the principal's tenants, each site and group labelled with its tenant."""
    group_tenant = {g['name']: g.get('tenant') or 'default' for g in st.list_groups()}
    allowed = scope.tenants()
    keep = (lambda t: True) if allowed is None else (lambda t: t in allowed)
    tenants = {t['id']: t for t in st.list_tenants()}
    sites = [{**s, 'tenant': group_tenant.get(s.get('grp'), 'default')} for s in ov['sites']]
    groups = [{**g, 'tenant': group_tenant.get(g['name'], 'default')} for g in ov['groups']]
    out = {**ov, 'sites': [s for s in sites if keep(s['tenant'])],
           'groups': [g for g in groups if keep(g['tenant'])],
           'tenants': [t for i, t in tenants.items() if keep(i)],
           'scope': {'msp': scope.msp, 'roles': {i: scope.role_in(i) for i in tenants if keep(i)}}}
    if not scope.msp:
        out['federated'] = None                          # MSP-wide
    return out


def usage(st, month, scope=None, fmt='json'):
    rows = st.usage(month)
    if scope is not None and scope.tenants() is not None:
        rows = [r for r in rows if r['tenant'] in scope.tenants()]
    if fmt == 'csv':
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=['month', 'tenant', 'name', 'sites', 'site_days', 'alerts', 'actions'])
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, 0) for k in w.fieldnames})
        return buf.getvalue()
    return rows
