# Entity Linking Strategy

## Scope and evidence constraints

Links are generated only from the CERT LDAP snapshots and the normalized
`logon.csv`, `file.csv`, and `device.csv` events. A link is a scored
relationship hypothesis, not an ownership assertion. No link is created just
because two entities appear in the same registry.

The CERT `device.csv` schema contains `id`, `date`, `user`, `pc`, and
`activity`; it does not contain a USB serial, peripheral identifier, or
peripheral model. Consequently, USB references can identify only observed
connection activity records, not physical USB devices. Such targets are
represented as `USB-ACT-<stable digest>` and explicitly marked as
`USB_ACTIVITY` in metadata. The engine does not create persistent USB-device
identity or ownership links.

## Link types

| Source -> Target | Relationship | Evidence |
|---|---|---|
| USER -> DEVICE | `USES` | Successful `LOGIN_SUCCESS` events pairing a user with an endpoint. Repeated observations strengthen confidence; this is not ownership. |
| USER -> FILE | `ACCESSED` | `FILE_ACCESS` events pairing the user with a source filename. |
| DEVICE -> FILE | `ACCESSED` | `FILE_ACCESS` events pairing the endpoint with a source filename. |
| USER -> USB activity | `USED_USB` | A `USB_INSERT` event's user and endpoint, plus a successful login for the same user on the same endpoint in the preceding 15 minutes. |
| DEVICE -> USB activity | `RECORDED_USB_ACTIVITY` | The endpoint recorded the specific `USB_INSERT` observation. This does not identify the peripheral. |

The last two link types target an observed activity record, not a physical USB
entity. USB removal events are retained in normalized telemetry but do not
establish a USB-use link.

## Confidence model

| Confidence | Label |
|---|---|
| 0.95-1.00 | Very Strong |
| 0.85-<0.95 | Strong |
| 0.70-<0.85 | Moderate |
| 0.50-<0.70 | Weak |
| <0.50 | Unverified |

Confidence is an evidence strength score in the range 0.0-1.0, not a calibrated
probability. The adjacent bands use half-open intervals to avoid overlap at
0.85 and 0.95.

### Repeated user/device or user/file observations

For `USES` and `ACCESSED` links, `n` is the number of matching source events:

`confidence = n / (n + 2)`

This produces 0.33 for one observation (unverified), 0.71 for five (moderate), and
0.96 for 50 (very strong). `evidence_count` is `n`; first and last event times
bound the observed activity.

Example: five successful logons by one user on one endpoint create a
`USER -> DEVICE` `USES` link with confidence 0.71 and evidence count 5.

### USB insertion correlations

An insertion is eligible for a `USER -> USB activity` link only if a
`LOGIN_SUCCESS` for the same user and endpoint occurred no more than 15
minutes earlier. Among eligible logons, the closest preceding logon is used.
For a time gap `t` in seconds:

`confidence = 0.75 + 0.25 * exp(-t / 300)`

The matching login and USB insertion are counted as two evidence records.
Example: a login at 09:00 and an insertion at 09:03 on the same endpoint yield
confidence about 0.89. A USB insertion without a matching recent login does
not receive a user link.

The `DEVICE -> USB activity` link has confidence 0.99 because the source event
explicitly records the endpoint and insertion activity; its metadata still
identifies the target as an activity observation, not a peripheral.

## Stable identifiers and reproducibility

User and endpoint IDs are taken from `users.json` and `devices.json`. File
targets use a SHA-256 digest of the case-folded source filename, avoiding
filename disclosure in IDs and making the ID independent of record order.
USB-activity targets use a SHA-256 digest of the source log and source record
ID. Links are sorted by source, target, and relationship before sequential
`LINK000001` IDs are assigned. The normalized event merger resolves equal
timestamps by source-log name and preserves source row order within each log.

## Limitations

- `file.csv` has no action column, so file links indicate the observed
  `FILE_ACCESS` normalization only; they do not distinguish create, modify,
  copy, or delete.
- Endpoint identity is the CERT `pc` value. The data does not establish
  exclusive endpoint ownership.
- A physical USB device cannot be linked or tracked across insertions because
  no peripheral identity is present in the inspected CERT fields.
