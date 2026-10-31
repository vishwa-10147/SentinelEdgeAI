# Beta programme (Phase 8)

**Goal:** 30 days at 3–5 friendly sites with no outage caused by the appliance, and published performance and detection numbers from real traffic.

## Site profile

| Profile | Count | Hardware | Preset |
|---|---|---|---|
| Home lab / small office | 1–2 | Pi 5, passive (mirror port) | `home` → `office` after week 2 |
| Office | 1–2 | Pi 5 sensor + brain | `office` |
| OT / lab network | 1 | Pi 5, passive only | `ot` |
| Multi-site | 1 operator with 2–3 sites | one Pi per site + a fleet server | `office`, rolled out from a fleet template |

## Timeline

| Week | Activity | Exit check |
|---|---|---|
| 0 | Install with `install.sh`, `harden_os.sh --apply`, backup taken, monitoring connected | health checks green, backup restorable |
| 1 | Detection only (dry run); analysts label alerts (true / false positive); response tuning in `recommend` | false-positive rate measured per detector; trust scores reviewed |
| 2 | Tune policy; enable enforcement with approval gate | zero blocks of protected hosts |
| 3–4 | Automatic graduated response (approval period still on for risk ≥ 75) | no outage caused by the appliance |
| 4 | Collect metrics and labelled alerts; exit interview | report published |

## What is measured

* Availability: appliance-caused outages (target 0), watchdog fail-open events, rollbacks.
* Detection: precision per detector from analyst labels (`/api/alerts/feedback`), alerts per day, confirmed vs unconfirmed.
* Performance: packets/s, decision latency p99, dropped packets, CPU/temperature (Grafana operations dashboard).
* Operations: update and restore exercised at least once per site; one fleet rollout across the multi-site operator, including a deliberate failed update that must pause it.
* Learning: how often response tuning's recommendation differs from the playbook, and whether operators agree; one federated round across the sites, with the shadow model compared to the local one.
* Robustness: any `capture_overload` alerts, and what caused them.
* Compliance: the ISO 27001 / NIS2 report per site at the start and the end (how many gaps were closed).

## Status

Not yet started. Done: public-dataset evaluation (docs/EVALUATION.md), flood safety, the fleet console. Still open: the external penetration test (must come first), a real SIEM end-to-end test, a Jetson for the two-node sites, and recruiting the sites.
