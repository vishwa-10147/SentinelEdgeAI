# Hosted fleet console

Run the fleet server and the console on any Linux host or cloud VM (amd64 or arm64), without packet capture
or enforcement. Appliances enrol with it over mutual TLS and keep working fully offline when it is
unreachable: it only distributes templates, rollouts, remote actions and shared indicators, and collects
compact status reports and alert summaries (never flows or packets).

```bash
cd deploy/fleet-hosted
FLEET_HOSTNAME=fleet.example.org docker compose up -d --build
printf '%s' 'a-long-admin-password' | docker compose exec -T console sh -c \
  'cat > /tmp/pw && python -m core.auth create-user --username admin --role admin --password-file /tmp/pw; rm /tmp/pw'
docker compose exec fleet python -m fleet code --group default      # prints the enrolment command for a site
```

On each appliance: `python -m fleet enroll https://fleet.example.org:9444 <code> <CA fingerprint>`.

* **Ports:** 9443 console (HTTPS; a self-signed certificate is created on first start: replace
  `data/console-tls/cert.pem` / `key.pem` in the volume, or put your reverse proxy in front), 9444 fleet
  server (mutual TLS; must reach the containers end to end, because sites pin the fleet CA).
* **Hardening:** both containers run as an unprivileged user with all capabilities dropped and no new
  privileges; the fleet server's root file system is read-only. State is in the `fleet-data` volume:
  back it up (`docker run --rm -v fleet-hosted_fleet-data:/d -v $PWD:/b busybox tar czf /b/fleet.tgz /d`).
* **Sign-in:** the first Admin enrols an authenticator app at first sign-in; SSO (OIDC/SAML) and LDAP work
  as on an appliance.

Verified on a Raspberry Pi 5 (2026-11-01): the stack built and started, the console answered over HTTPS, and
an appliance enrolled with the pinned CA and delivered a report.
