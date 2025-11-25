# Security Backend (Go)

This folder contains the Go HTTP API server that orchestrates the C++ simulator CLI and serves graph/pda/dfa endpoints consumed by the visualizer.

Prerequisites

- Go 1.20+ (to build/run the backend)
- The C++ simulator binary (built from `../security-dfa-gen`) — the backend calls this binary to run DFA/PDA simulations.

Build the C++ simulator

```bash
cd ../security-dfa-gen
make
# the build produces the CLI used by the backend (e.g. `bin/api`)
```

Run the backend (development)

```bash
cd security-backend
go run ./cmd/server
```

By default the server listens on port `8080` and exposes the API under `/api`.

Important API endpoints

- `POST /api/session` — start a new interactive session. Returns `{ session_id }`.
- `GET /api/graph` — returns DFA `GraphData` (nodes/edges) used by the visualizer's DFA view.
- `GET /api/pda/graph` — returns PDA `GraphData` for the PDA view.
- `POST /api/request/process` — send a full request (packets array) for processing. Example payload:

```json
{
  "session_id": "...",
  "host_id": "192.168.1.100",
  "packets": [ { "proto": "tcp", "service": "http", "conn_state": "S0", "data": "GET /" } ],
  "threshold": 1
}
```

The response contains a `pda` validation result, and an array of per-packet DFA responses (`packets`), each including `is_malicious` and step traces.

- `POST /api/dfa/step` — run DFA for a single packet (used for step-by-step DFA playback).
- `GET /api/derivation?session_id=...` — get grammar derivation steps for the current session.

Templates and frontend integration

- The frontend loads templates from `security-visualizer/public/templates.json`. To add or edit templates, modify that JSON file and refresh the frontend.

Threshold semantics

- The `threshold` parameter in `/api/request/process` indicates how many packet-level DFA `is_malicious` detections are required to flag the entire request as malicious. The backend aggregates packet detections and sets `is_malicious` in the top-level response when the number of flagged packets >= threshold.

Troubleshooting

- If the backend cannot find or execute the C++ CLI binary, ensure `security-dfa-gen` was built (`make`) and the resulting binary is reachable by the backend (relative paths assume `../security-dfa-gen/bin/api`).
- If `go run` fails, inspect the error message (sometimes port bind or missing environment). Restart the program after fixing the issue.
- If the frontend reports 404 on `/templates.json`, ensure the frontend dev server is serving the `public` directory and the file exists.

Contact / next steps

If you want, I can:

- Add a small `Makefile` task to build the C++ CLI and start the backend in one step.
- Add example `curl` requests for `/api/request/process` to exercise the API from the command line.
