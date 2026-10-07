# Phase 5: Attack Chain Builder

Run from the project root:

```powershell
python -m reconstruction.chain_builder
```

The builder consumes `data/processed/detected_stages.json`,
`data/normalized/normalized_events.json`, the entity registries, and (when
present) `data/processed/entity_links.json`. It groups stages by user and
endpoint, sorts them by start time, and recognizes these declared patterns:

- `COLLECTION` followed by matching `EXFILTRATION` becomes
  `INSIDER_DATA_THEFT`.
- A preceding `INITIAL_ACCESS` followed by `COLLECTION` and matching
  `EXFILTRATION` becomes `COMPROMISED_USER_DATA_THEFT`.

Collection evidence is matched to an exfiltration stage using the evidence
carried into that stage by Phase 4; legacy inputs without that overlap fall
back to same-user/device chronology. Initial access must precede collection.
Chains are emitted only when a collection/exfiltration pattern is supported.

Risk points are 40 for collection and 50 for exfiltration, plus 10 when the
largest stage file count exceeds 100, capped at 100. Levels are LOW (0-39),
MEDIUM (40-69), HIGH (70-89), and CRITICAL (90-100). Scores are rule-based
priorities, not calibrated probabilities.

The graph is JSON and contains user, device, event, file, and observed USB
activity nodes. Existing confidence-scored links are included only where both
endpoints are represented. USB nodes refer to CERT activity records; they do
not imply an identified physical peripheral.

Output is written atomically to `data/processed/attack_chains.json`. Evidence
event IDs are checked against the normalized store; `CERT-HTTP:` initial
access evidence is checked against the corresponding raw CERT HTTP record.
