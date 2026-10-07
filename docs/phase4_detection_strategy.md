# Phase 4 Stage Detection Strategy

## Initial access

The detector takes URLs labeled `0` in
`data/raw/phishing/PhiUSIIL_Phishing_URL_Dataset.csv` as phishing candidates
and checks for exact URL visits in CERT `http.csv`. A finding is created only
when the source HTTP record supplies a user, endpoint, timestamp, and record
ID. Its evidence references use `CERT-HTTP:<source-record-id>` because the
current normalized event store does not include HTTP events.

The CERT SMS spam dataset has only a ham/spam label and message content. It
does not identify a user, endpoint, or timestamp, and is therefore not
attributed to an account or emitted as an attack stage.

## Collection

The rule triggers on at least 20 distinct filenames for the same user and
endpoint in a rolling 10-minute window. CERT's observed maximum was 27 distinct
filenames in a 10-minute window; a threshold of 50 would produce no collection
findings in this data. Twenty is a high-volume indicator, not a claim that
collection is malicious. Repeated access to the same filename does not
increase the distinct-file count.

Confidence starts at 0.80 at the threshold and increases by 0.002 per
additional distinct filename, capped at 0.99. This is a heuristic score and
must not be interpreted as a calibrated probability.

## Exfiltration

An exfiltration candidate requires a detected collection stage and a later
`USB_INSERT` event for the same user and endpoint within 15 minutes of the
collection stage's end. A USB insertion without qualifying collection never
creates an exfiltration stage. Since the CERT device stream does not identify
the physical peripheral, the output records the insertion event but does not
claim persistent USB identity or ownership.

## Operational caveats

- Dataset label semantics are consumed as encoded (`0` is treated as
  phishing); the result is an IOC match, not proof that a user was compromised.
- HTTP evidence is referenced by raw CERT record ID, not an `EVT` ID, because
  HTTP data is not part of the Phase 2 normalized event store.
- Thresholds are deterministic defaults and should be re-calibrated against
  additional benign activity and analyst feedback before production alerting.
