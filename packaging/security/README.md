Security hardening notes

Quick steps applied/available:
- Services run as a non-root user (`vishwa` by default) and the health runtime env is provided from `/run/sentinel/health.env` with 600 perms.
- Systemd units include `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` and `NoNewPrivileges=false` where needed.

Recommendations:
- Lock down SSH and use key-based auth; disable password login.
- Use a centralized secrets store (HashiCorp Vault) for production secrets.
- Enable `systemd` service sandboxes (`PrivateTmp=yes`, `ProtectSystem=full`) where compatible.
- Regularly rotate credentials in `/etc/sentinel/health.env` and consider an automated agent.
