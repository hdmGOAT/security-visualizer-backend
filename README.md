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

Windows notes

- The backend will prefer a Windows-built CLI named `api.exe` when present and will fall back to the non-.exe binary if the `.exe` is not found (this supports running under WSL or when only the Linux binary is available). Place the simulator binary under `../security-dfa-gen/bin/` (or `external/bin/` depending on your setup) so the backend can locate it.
- If you want native Windows support it is easiest to build the C++ simulator on Windows (MSYS2 / Visual Studio toolchain) and ensure the output binary is named `api.exe` in the expected location. Alternatively use WSL and build the existing Makefile there.


Important API endpoints

- `GET /api/graph` — returns DFA `GraphData` (nodes/edges) used by the visualizer's DFA view.
- `GET /api/pda/graph` — returns PDA `GraphData` for the PDA view.
  - `POST /api/request/process` — send a full request (packets array) for processing. Example payload:
 
 ```json
 {
   "packets": [ { "proto": "tcp", "service": "http", "conn_state": "S0", "data": "GET /" } ],
   "threshold": 1
 }
 ```

The response contains a `pda` validation result, and an array of per-packet DFA responses (`packets`), each including `is_malicious` and step traces.

- `POST /api/dfa/step` — run DFA for a single packet (used for step-by-step DFA playback).
- `POST /api/derivation` — get grammar derivation steps for a provided packet (POST body: `{ "packet": {...} }`).

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
