# CERT Dataset Mapping

This mapping is based on the files present under `data/raw/cert/`. The CERT
directory contains five event CSVs and 18 monthly LDAP snapshots (December
2009 through May 2011). The expected `psychometric.csv` file was not present
when the directory was inspected, so its schema and sample cannot be verified.

## logon.csv

### Purpose

Records user logon and logoff activity on endpoint computers. The observed
sample contains a `Logon` activity; the file does not expose a separate
authentication result field.

### Columns

| Column | Meaning |
|----------|----------|
| `id` | Unique identifier for the logon activity record. |
| `date` | Timestamp of the activity, formatted as month/day/year and time. |
| `user` | User account identifier associated with the activity. |
| `pc` | Endpoint computer identifier. |
| `activity` | Activity label, such as `Logon`; other values should be confirmed from the file. |

### Example Record

`{X1D9-S0ES98JV-5357PWMI},01/02/2010 06:49:00,NGF0157,PC-6056,Logon`

### Candidate Event Types

The inspected activity values are `Logon` and `Logoff`, normalized to
`LOGIN_SUCCESS` and `LOGOUT` respectively. No failure value or separate
authentication result field was observed, so `LOGIN_FAILURE` is not emitted
from this source.

### Candidate Entities

User, Device

## device.csv

### Purpose

Records device connection activity associated with a user and endpoint.

### Columns

| Column | Meaning |
|----------|----------|
| `id` | Unique identifier for the device activity record. |
| `date` | Timestamp of the activity. |
| `user` | User account identifier associated with the activity. |
| `pc` | Endpoint computer identifier. |
| `activity` | Device activity label, such as `Connect`; this sample alone does not establish every possible value or device subtype. |

### Example Record

`{J1S3-L9UU75BQ-7790ATPL},01/02/2010 07:21:06,MOH0273,PC-6699,Connect`

### Candidate Event Types

The inspected activity values are `Connect` and `Disconnect`, normalized to
`USB_INSERT` and `USB_REMOVE` respectively. The source has no explicit device
subtype or access activity in the observed columns.

### Candidate Entities

User, Device

## file.csv

### Purpose

Records file-related activity and includes the file name and associated
content. No explicit action column is present, so access/create/modify
classification requires additional evidence.

### Columns

| Column | Meaning |
|----------|----------|
| `id` | Unique identifier for the file activity record. |
| `date` | Timestamp associated with the record. |
| `user` | User account identifier associated with the record. |
| `pc` | Endpoint computer identifier. |
| `filename` | Name of the file. |
| `content` | Text content associated with the file record. |

### Example Record

`{L9G8-J9QE34VM-2834VDPB},01/02/2010 07:23:14,MOH0273,PC-6699,EYPC9Y08.doc,"D0-CF-11-E0-A1-B1-1A-E1 during difficulty overall ..."`

The `content` value is abbreviated here for readability.

### Candidate Event Types

`FILE_ACCESS`. The inspected schema has no action/activity column, so file
creation, modification, deletion, and copy actions cannot be inferred from
this source alone.

### Candidate Entities

User, Device, FileEntity

## email.csv

### Purpose

Records email activity, including sender, recipients, endpoint, message size,
attachment count, and content.

### Columns

| Column | Meaning |
|----------|----------|
| `id` | Unique identifier for the email activity record. |
| `date` | Timestamp associated with the email record. |
| `user` | User account identifier associated with the activity. |
| `pc` | Endpoint computer identifier. |
| `to` | Semicolon-separated primary recipient addresses. |
| `cc` | Semicolon-separated carbon-copy recipient addresses. |
| `bcc` | Semicolon-separated blind-carbon-copy recipient addresses; may be empty. |
| `from` | Sender email address. |
| `size` | Message size; the observed sample value is numeric, but the unit is not specified in the columns. |
| `attachments` | Attachment count. |
| `content` | Message body/content text. |

### Example Record

`{R3I7-S4TX96FG-8219JWFF},01/02/2010 07:11:45,LAP0338,PC-5758,"Dean.Flynn.Hines@dtaa.com;Wade_Harrison@lockheedmartin.com",Nathaniel.Hunter.Heath@dtaa.com,,Lynn.Adena.Pratt@dtaa.com,25830,0,"middle f2 systems 4 july techniques powerful ..."`

The `content` value is abbreviated here for readability.

### Candidate Event Types

`EMAIL_SENT`, `EMAIL_RECEIVED`

### Candidate Entities

User, Device, Email, FileEntity (attachments), Domain

## http.csv

### Purpose

Records a user's web/HTTP activity on an endpoint, including the visited URL
and associated content.

### Columns

| Column | Meaning |
|----------|----------|
| `id` | Unique identifier for the HTTP activity record. |
| `date` | Timestamp of the activity. |
| `user` | User account identifier associated with the activity. |
| `pc` | Endpoint computer identifier. |
| `url` | URL associated with the HTTP activity. |
| `content` | Text content associated with the HTTP record. |

### Example Record

`{V1Y4-S2IR20QU-6154HFXJ},01/02/2010 06:55:16,LRR0148,PC-4275,http://msn.com/The_Human_Centipede_First_Sequence/katsuro/arjf309875127.htm,"remain representatives consensus concert ..."`

The `content` value is abbreviated here for readability.

### Candidate Event Types

`URL_VISITED`, `HTTP_REQUEST`

### Candidate Entities

User, Device, URL, Domain

## LDAP/ (monthly CSV snapshots)

### Purpose

Contains monthly LDAP-style directory snapshots describing employees,
accounts, roles, organizational placement, and supervisor relationships.
All 18 present monthly files have the same header. These are snapshots, not
event logs; changes between snapshots can be derived by comparing records.

Files present: `2009-12.csv`, `2010-01.csv` through `2010-12.csv`, and
`2011-01.csv` through `2011-05.csv`.

### Columns

| Column | Meaning |
|----------|----------|
| `employee_name` | Employee's display name. |
| `user_id` | Directory user/account identifier. |
| `email` | Employee email address. |
| `role` | Job role or title. |
| `business_unit` | Business unit identifier. |
| `functional_unit` | Functional unit identifier/name. |
| `department` | Department identifier/name. |
| `team` | Team identifier/name. |
| `supervisor` | Supervisor's display name. |

### Example Record

`Calvin Edan Love,CEL0561,Calvin.Edan.Love@dtaa.com,ComputerProgrammer,1,2 - ResearchAndEngineering,2 - SoftwareManagement,3 - Software,Stephanie Briar Harrington`

### Candidate Event Types

`IDENTITY_SNAPSHOT`, `USER_ATTRIBUTE_CHANGE` (derived by comparing snapshots;
not directly represented as an event in an individual file).

### Candidate Entities

User, Email, organizational units (business unit, functional unit, department,
team)

## psychometric.csv (not present)

### Purpose

The expected file was not found under `data/raw/cert/`; its purpose cannot be
verified from the available inputs.

### Columns

| Column | Meaning |
|----------|----------|
| Not available | No `psychometric.csv` file was present to inspect. |

### Example Record

Not available; the dataset file is missing.

### Candidate Event Types

Not determined.

### Candidate Entities

Not determined.

## Summary

| Dataset | Event Category | Main Entities |
|----------|----------------|---------------|
| `logon.csv` | Authentication/session activity | User, Device |
| `device.csv` | Device connection activity | User, Device |
| `file.csv` | File-related activity | User, Device, FileEntity |
| `email.csv` | Email activity | User, Device, Email, FileEntity, Domain |
| `http.csv` | Web/HTTP activity | User, Device, URL, Domain |
| `LDAP/` monthly snapshots | Identity and organization directory data (snapshot, not event stream) | User, Email, organizational units |
| `psychometric.csv` | Not available (file missing) | Not determined |
