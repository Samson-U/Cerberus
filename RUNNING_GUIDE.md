# Running Cerberus

Use two terminals. These commands start the FastAPI backend and the Vite
frontend from the repository root.

## Backend

```powershell
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
uvicorn api.app:app --reload
```

Expected output:

```text
INFO: Uvicorn running on http://127.0.0.1:8000
```

If a previous demo session needs to be cleared before launching the UI, use:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/simulation/reset -Method Post
```

## Frontend

In a second terminal, from the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Expected output:

```text
Local: http://localhost:5173
```

## Demo

1. Start the backend.
2. Start the frontend.
3. Open http://localhost:5173.
4. The dashboard reads only simulator runtime data. On a clean run it starts
   with zero simulated events, threats, and investigations.
5. Click **Start Simulation** on the dashboard. This creates a new isolated
   session and starts the normal 70% benign / 30% attack scenario stream.
6. Watch generated events appear and incidents get reconstructed live.
7. To replay a selected scenario, open **Settings → Demo Mode**, choose Insider
   Data Theft, Malware Infection, or Lateral Movement, then enable Demo Mode.
8. Click **Reset Demo** to stop the stream and clear runtime events, incidents,
   timelines, reports, and session state.

Simulation output is stored under `data/runtime/`. CERT source data and
historical processed artifacts are not used as the dashboard's incident,
timeline, report, or graph source and are not modified by simulation.
