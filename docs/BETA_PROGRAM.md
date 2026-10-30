# Beta programme (Phase 6 exit criterion)

**Goal:** 30 days at 3–5 friendly sites with no outage caused by the appliance, and published performance and detection numbers from real traffic.

## Site profile

| Profile | Count | Hardware | Preset |
|---|---|---|---|
| Home lab / small office | 1–2 | Pi 5, passive (mirror port) | `home` → `office` after week 2 |
| Office | 1–2 | Pi 5 sensor + brain | `office` |
| OT / lab network | 1 | Pi 5, passive only | `ot` |

## Timeline

| Week | Activity | Exit check |
|---|---|---|
| 0 | Install with `install.sh`, `harden_os.sh --apply`, backup taken, monitoring connected | health checks green, backup restorable |
| 1 | Detection only (dry run); analysts label alerts (true / false positive) | false-positive rate measured per detector |
| 2 | Tune policy; enable enforcement with approval gate | zero blocks of protected hosts |
| 3–4 | Automatic graduated response (approval period still on for risk ≥ 75) | no outage caused by the appliance |
| 4 | Collect metrics and labelled alerts; exit interview | report published |

## What is measured

* Availability: appliance-caused outages (target 0), watchdog fail-open events, rollbacks.
* Detection: precision per detector from analyst labels (`/api/alerts/feedback`), alerts per day, confirmed vs unconfirmed.
* Performance: packets/s, decision latency p99, dropped packets, CPU/temperature (Grafana operations dashboard).
* Operations: update and restore exercised at least once per site.

## Status

Not yet started. Prerequisites still open: a real SIEM end-to-end test, a Jetson for the two-node sites, evaluation on public datasets.
