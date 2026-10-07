# Phase 6: Attack Timeline Builder

Run from the project root:

```powershell
python -m reconstruction.timeline_builder
```

The builder reads attack chains, detected stages, and normalized events. For
each chain it retrieves every referenced `EVT` record and also includes
same-user/same-device events within the attack bounds as timeline context.
Timeline entries are independently sorted by parsed timestamp; source order
is never trusted.

Each normalized event entry includes a human-readable description and the full
source event object. Stage annotations come from the stage evidence IDs.
Collection file evidence is labeled `COLLECTION`; an exfiltration stage
annotates its USB insertion evidence as `EXFILTRATION`, rather than relabeling
all reused collection evidence. `CERT-HTTP:` initial-access evidence is
resolved to its actual raw `http.csv` record and represented separately from
normalized event records.

Event descriptions are centralized in `EVENT_DESCRIPTIONS` in
`reconstruction/timeline_builder.py`. Missing evidence, invalid stage
references, malformed event records, or non-chronological output raise an
error instead of creating a partial success-shaped timeline.

Output is written atomically to `data/processed/attack_timelines.json`.
