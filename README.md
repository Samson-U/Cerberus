# Cerberus

### Cyber Threat Intelligence and Attack Reconstruction

Cerberus correlates security events across users, devices, IP addresses, URLs, processes, files, and network activity to reconstruct suspicious activity as an ordered attack chain.

The system is designed to help an analyst answer:

- What happened?
- Which entities were involved?
- In what order did the activity occur?
- Which events support each attack stage?
- How confident is the reconstruction?
- What should be investigated next?

---

## 1. What the Project Does

Modern security environments produce large volumes of logs from different systems. Individual events may appear harmless when viewed in isolation, while their combination can reveal a coordinated attack.

Cerberus normalizes events from multiple sources into a common event model, links related entities, constructs an entity graph, correlates suspicious activity, and reconstructs the resulting attack as a chronological chain.

The investigation interface presents:

- Active threat alerts
- Attack timelines
- Attack stages
- Supporting evidence
- Related users, devices, IPs, URLs, files, and processes
- Entity relationships
- Risk and confidence
- Human-readable incident explanations

---

## 2. System Architecture

```text
                    Security Events
                           |
                           v
                Canonical Event Schema
                           |
                           v
                   Entity Resolution
                           |
                           v
                      Entity Graph
                           |
                           v
                   Attack Correlation
                           |
                           v
                  Attack Reconstruction
                           |
              +------------+------------+
              |            |            |
              v            v            v
          Timeline      Evidence     Confidence
              |            |            |
              +------------+------------+
                           |
                           v
                  Ollama Explanation
                           |
                           v
                   Frontend Dashboard
```

### Processing Pipeline

#### Event Normalization

Events from different datasets and security sources are converted into a common canonical event schema.

#### Entity Resolution

Users, devices, IP addresses, URLs, files, processes, malware, and other entities are linked using identifiers and contextual evidence.

#### Entity Graph

Related entities are represented as nodes and relationships. This allows activity to be followed across multiple security sources.

#### Attack Correlation

Related events are grouped using temporal, entity, behavioral, and event relationships.

#### Attack Reconstruction

Correlated events are ordered chronologically and mapped to attack stages such as Initial Access, Execution, Discovery, Collection, and Exfiltration.

#### Evidence

Every reconstructed stage retains references to the events that support the conclusion.

#### Explanation

Ollama receives the verified reconstruction and produces a human-readable explanation for the analyst.

---

## 3. Key Features

- Multi-source security event correlation
- Canonical event normalization
- Entity resolution with confidence
- Entity graph construction
- Attack chain reconstruction
- Chronological attack timeline
- Evidence-backed attack stages
- Risk and confidence scoring
- Threat alert interface
- Incident investigation dashboard
- Interactive entity graph
- Local incident explanation using Ollama
- Support for attack and benign scenarios
- Controlled demonstration scenarios for reproducible evaluation

---

## 4. Technologies Used

| Component | Technology |
|---|---|
| Frontend | React / Vite |
| Backend | Python / FastAPI |
| Data Processing | Python / Pandas |
| Graph Processing | NetworkX |
| AI Explanation | Ollama |
| Language Model | Llama-family model through Ollama |
| Data Formats | CSV / JSON |
| API | REST |
| Version Control | Git / GitHub |

> Replace or extend this table with the exact libraries used by the final implementation before submission.

---

## 5. Datasets

Cerberus uses multiple security datasets with different roles in the detection and reconstruction pipeline.

| Dataset | Role |
|---|---|
| CERT Insider Threat | Primary multi-source enterprise activity and attack reconstruction |
| Network Intrusion Dataset | Network attack and traffic analysis |
| Malware Dataset | Malware and process activity detection |
| Phishing URL Dataset | Malicious URL detection |
| SMS Spam Dataset | Phishing and spam signal detection |
| Synthetic Enterprise Dataset | Controlled attack reconstruction and evaluation |

### CERT Insider Threat

The CERT Insider Threat dataset is used as a primary reconstruction source because it contains multiple forms of enterprise activity, including authentication, device usage, file activity, email, and web activity.

The other datasets provide supporting threat signals and detection evidence.

Large source datasets should not be committed to this repository. A small reproducible sample can be stored under `data/sample/`, while the README documents the required dataset preparation.

---

## 6. Canonical Event Model

All supported event sources are converted into a common representation before correlation.

Example:

```json
{
  "event_id": "EVT000001",
  "timestamp": "2026-01-01T09:00:00Z",
  "event_type": "URL_VISITED",
  "event_category": "WEB_ACTIVITY",
  "source_system": "Browser",
  "source_log": "chrome_history",
  "severity": "low",
  "confidence": 1.0,
  "user_id": "USR001",
  "device_id": "DEV001",
  "src_ip": "10.0.5.22",
  "dst_ip": "185.142.10.21",
  "session_id": "SES001",
  "related_entities": [
    "USR001",
    "DEV001",
    "URL001",
    "DOMAIN001"
  ],
  "metadata": {
    "url": "https://example.com",
    "browser": "Chrome"
  },
  "raw_event_ref": "browser_log_12345"
}
```

This allows events from different sources to be processed by the same downstream reconstruction pipeline.

---

## 7. Entity Graph

Cerberus represents security entities as a graph.

Typical entities include:

```text
User
Device
IP Address
Domain
URL
Process
File
Email
SMS
Malware
Network Connection
```

Example relationship:

```text
User
  |
  | USES
  v
Device
  |
  | CONNECTS_TO
  v
IP Address
  |
  | HOSTS
  v
Domain
```

Entity relationships can include a confidence value and supporting evidence.

The entity graph answers:

> What is connected to what?

The attack reconstruction identifies:

> Which connected path represents the suspicious activity?

---

## 8. Attack Reconstruction

A reconstructed incident is represented as an ordered chain of evidence.

Example:

```text
09:02  Unusual authentication
          |
          v
09:10  Sensitive file access
          |
          v
09:15  USB device connected
          |
          v
09:18  Files copied
          |
          v
09:20  External network activity
          |
          v
09:22  Suspected exfiltration
```

Each stage contains supporting event identifiers, timestamps, entities, confidence, and other available evidence.

Example:

```json
{
  "stage": "COLLECTION",
  "confidence": 0.91,
  "evidence": [
    "EVT0042",
    "EVT0047",
    "EVT0051"
  ]
}
```

---

## 9. Evidence-Backed Detection

Cerberus does not treat an explanation as evidence.

Every reconstructed attack stage should be backed by source events.

Example:

```text
Stage: Collection

Evidence:
- EVT0042 — Sensitive file accessed — 09:10
- EVT0047 — Multiple files read — 09:12
- EVT0051 — Files copied to removable device — 09:18
```

The explanation layer receives these verified facts instead of independently inventing events, timestamps, entities, or attack stages.

---

## 10. Installation

### Requirements

- Python 3.10+
- Node.js 18+
- npm
- Git
- Ollama

### Clone the Repository

```bash
git clone https://github.com/<username>/cerberus.git
cd cerberus
```

### Backend Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

---

## 11. Ollama Configuration

Cerberus uses Ollama for local incident explanation.

Install Ollama and download the model configured by the project:

```bash
ollama pull <model-name>
```

Start the Ollama service:

```bash
ollama serve
```

By default, the application expects Ollama at:

```text
http://localhost:11434
```

Create a local `.env` file based on `.env.example`.

Example:

```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=<model-name>
BACKEND_URL=http://localhost:8000
FRONTEND_URL=http://localhost:5173
```

Do not commit the real `.env` file.

---

## 12. Running the System

### Start the Backend

From the project root:

```bash
uvicorn backend.main:app --reload
```

The backend will be available at:

```text
http://localhost:8000
```

### Start the Frontend

In another terminal:

```bash
cd frontend
npm run dev
```

Open the local URL displayed by Vite.

---

## 13. Reproducing the Demonstration

The repository should contain a controlled demonstration scenario so that the demonstrated result can be reproduced without requiring the evaluator to manually construct an attack.

Example:

```bash
python scripts/run_demo.py --scenario insider_exfiltration
```

The demonstration scenario represents an insider data-exfiltration sequence:

```text
1. Unusual user authentication
2. Sensitive file access
3. USB device connection
4. File copying activity
5. External network connection
6. Suspected data exfiltration
```

The demonstration passes the events through the Cerberus pipeline:

```text
Demo Events
    |
    v
Event Normalization
    |
    v
Entity Resolution
    |
    v
Graph Construction
    |
    v
Attack Correlation
    |
    v
Attack Reconstruction
    |
    v
Evidence + Confidence
    |
    v
Ollama Explanation
    |
    v
Dashboard
```

After execution, open the frontend and navigate to the generated incident.

> Update the command above to match the final demo script and scenario name used in the repository.

---

## 14. Expected Demonstration Output

The demonstration should produce an incident similar to:

```text
Incident
└── Insider Data Exfiltration
    |
    ├── Authentication
    |   └── Unusual login
    |
    ├── Collection
    |   └── Sensitive files accessed
    |
    ├── Device Activity
    |   └── USB device connected
    |
    ├── Collection
    |   └── Files copied
    |
    └── Exfiltration
        └── External network activity
```

The investigation interface presents:

- Incident severity
- Affected user
- Affected device
- Attack timeline
- Attack stages
- Supporting evidence
- Related entities
- Entity graph
- Confidence
- Risk
- Ollama-generated explanation

---

## 15. Interface

### Threat Alert

The dashboard displays an alert when a high-confidence suspicious chain is detected.

Example:

```text
ACTIVE THREAT DETECTED

INSIDER DATA EXFILTRATION

Risk: HIGH
Confidence: 94%

User: jsmith
Device: DEV-023

4 correlated events

[View Investigation]
```

### Attack Investigation

The investigation view combines the reconstructed timeline, attack stages, evidence, risk, and related entities.

### Entity Graph

The graph view allows an analyst to inspect relationships between users, devices, files, processes, URLs, IP addresses, and other entities.

### AI Explanation

The explanation panel summarizes the verified reconstruction and highlights the evidence behind the conclusion.

---

## 16. Evaluation

Cerberus can be evaluated using attack and benign scenarios.

| Metric | Purpose |
|---|---|
| Precision | Correctness of detected attack activity |
| Recall | Coverage of attack activity |
| F1 Score | Combined precision and recall |
| False Positive Rate | Frequency of benign activity incorrectly flagged |
| Timeline Accuracy | Correct chronological ordering of events |
| Entity Linking Accuracy | Correct relationships between entities |
| Stage Identification | Correct attack-stage classification |
| Reconstruction Accuracy | Correctness of the complete attack chain |
| Root Cause Identification | Ability to identify the initiating activity |

No performance values are claimed in this README unless they are produced by the reproducible evaluation scripts.

---

## 17. Project Structure

```text
Cerberus/
├── backend/              # Backend API and services
├── frontend/             # Web dashboard
├── configs/              # Configuration
├── schemas/              # Event and entity schemas
├── parsers/              # Log and dataset parsers
├── correlation/          # Event/entity correlation
├── reconstruction/       # Attack reconstruction engine
├── simulation/           # Synthetic attack simulation
├── data/
│   ├── raw/              # Raw datasets
│   ├── processed/        # Processed datasets
│   ├── normalized/       # Canonical events
│   ├── runtime/          # Runtime data
│   └── synthetic/        # Synthetic scenarios
├── outputs/              # Generated results and reports
├── tests/                # Automated tests
├── docs/                 # Documentation
├── screenshots/          # Screenshots and demo assets
├── .gitignore
├── README.md
├── requirements.txt
└── RUNNING_GUIDE.md
```

Update this tree to reflect the final repository structure.

---

## 18. Screenshots

```text
docs/screenshots/
```


---

## 19. Security and Data Handling

Raw datasets may contain large volumes of security-related records. Large source datasets should not be committed to the public repository unless their redistribution is explicitly permitted.

The repository should contain only:

- Code
- Configuration examples
- Small reproducible samples
- Synthetic demonstration data
- Dataset preparation instructions
- Documentation

Dataset licenses and usage requirements must be followed for all external sources.

---


## 21. License

This project was developed for the Hacknex 2026 evaluation.

