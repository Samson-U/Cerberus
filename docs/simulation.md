# Live Simulation

Cerberus writes generated enterprise activity and its reconstructions into
isolated files under `data/runtime/`. It does not append to or replace
`data/normalized/normalized_events.json` or historical processed artifacts.
An adjacent write-ahead journal restores and replays an interrupted event append.
Each call to `POST /api/simulation/start` creates a new session and clears the
previous runtime session's events, incidents, timelines, reports, and statuses.
While there is no session, dashboard APIs return an empty demo view rather than
falling back to historical CERT incidents.

## Start and stop

Run the API as usual, then use:

```http
POST /api/simulation/start
Content-Type: application/json

{"interval_seconds": 5}
```

Stop generation without deleting its output:

```http
POST /api/simulation/stop
```

`GET /api/simulation/status` reports `running`, `session_id`, and `start_time`,
along with scenario counts, generated events, Demo Mode selection, and any
worker error. Normal operation selects
exactly seven benign and three attack scenarios per ten-scenario cycle. Attack
scenarios rotate across insider theft, malware infection, and lateral movement.

## Controlled Demo Mode

Start a single scenario repeatedly by setting `demo_mode` and `scenario`:

```json
{
  "demo_mode": true,
  "scenario": "MALWARE_INFECTION",
  "interval_seconds": 5
}
```

Supported selections are `INSIDER_THEFT`, `MALWARE_INFECTION`, and
`LATERAL_MOVEMENT`. The Settings page exposes the same control.

## Live data

- `GET /api/events/live?limit=50` returns recent canonical simulation events.
- `GET /api/incidents/live?limit=50` returns reconstructed simulation incidents.
- The frontend refreshes live lists and open investigation details every five
  seconds.
- `POST /api/simulation/reset` stops the producer and deletes only simulator
  runtime files, returning the demo view to zero. Historical CERT files are
  preserved.
