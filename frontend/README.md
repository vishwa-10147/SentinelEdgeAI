# Web console (React + Vite)

The console served by the API at `https://<device>:9000`. Release packages include a built copy (`frontend/dist/`), so a device never needs Node.js.

## Develop

```bash
cd frontend
npm ci
npm run dev          # http://127.0.0.1:5173, talking to the API set in VITE_API_BASE
npm run build        # -> frontend/dist (what the API serves and the package ships)
```

Node.js 20.19 or newer is required (Vite). `frontend/dist/` and `node_modules/` are not committed.

## Structure

| File | What it is |
|---|---|
| `src/App.jsx` | Layout, top bar, live WebSocket stream (cursor resume, resync, heartbeat watchdog), firewall window |
| `src/api.js` | API client: short-lived access token in memory, refresh cookie, `openSocket()` |
| `components/AuthScreens.jsx` | Sign-in, two-step sign-in, forced password change |
| `components/SetupWizard.jsx` | First-run setup: network role, placement, capture interface, response mode |
| `components/Topology*.jsx`, `DeviceDetail.jsx`, `Analytics*.jsx`, `FirewallActivity.jsx`, `Legend.jsx` | Network map, device panel, charts, firewall activity |
| `components/OperationsModal.jsx` | **Operations:** approvals and restrictions, policy YAML with checked diff, response tuning, sensors, model registry, feedback, evaluation, compliance |
| `components/TrustModal.jsx` | **Trust:** device trust scores with reasons, contain and release |
| `components/OtModal.jsx` | **OT devices:** industrial controllers, their masters and functions, micro-segmentation |
| `components/FleetModal.jsx` | **Fleet:** sites, groups and rollouts, templates, federated learning |
| `components/UsersModal.jsx`, `AuditModal.jsx` | Users and API tokens; hash-chained audit log |
| `components/PresenterMode.jsx` | Guided demo overlay |

Buttons appear only for roles allowed to use them (`hasRole` in `api.js`), but the API enforces every role itself (`tests/test_endpoint_roles.py`).
