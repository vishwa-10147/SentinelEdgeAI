# Live integration tests

End-to-end runs against real third-party software in Docker. They are not part of `pytest` (they need Docker,
network access to pull images and a few minutes each) and clean up after themselves.

| Script | What it proves | Images |
|---|---|---|
| `run_keycloak_sso.sh` | OIDC and SAML 2.0 sign-in through a real browser flow: a mapped analyst signs in over each protocol, an operator is refused without IdP MFA, a user in no mapped group is refused; Keycloak's own SAML signatures are verified | `quay.io/keycloak/keycloak:26.0` |
| `run_elastic.sh` | Alerts through the JSON-lines, syslog RFC 5424 and CEF sinks arrive in Elasticsearch through Filebeat (`deploy/elastic/filebeat.yml`) with their fields parsed | `elasticsearch:8.15.3`, `filebeat:8.15.3` |
| `run_thehive.sh` | An incident becomes a TheHive alert (severity, tags, devices as observables), is updated and resolved with the analyst's note | `strangebee/thehive:5.4`, `cassandra:4.1`, `elasticsearch:8.15.3` |

```bash
bash tests/live/run_keycloak_sso.sh
bash tests/live/run_elastic.sh
bash tests/live/run_thehive.sh      # about 4 minutes on a Raspberry Pi 5
```

Last run: 2026-11-01 on a Raspberry Pi 5, all passing.
