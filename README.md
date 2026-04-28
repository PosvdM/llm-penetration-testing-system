# LLM Penetration Testing System

An engineering prototype for an LLM-driven automated penetration testing system in authorized lab and competition scenarios.

## Current Status

This repository currently contains:

- backend skeleton based on FastAPI
- frontend skeleton based on React and Vite
- initial API routes for health checks and task overviews
- project planning and environment audit documents

## Repository Layout

```text
.
├─ backend/
├─ frontend/
├─ data/
├─ docs/
├─ scripts/
├─ PROJECT_PLAN.md
└─ DEV_ENV_AUDIT.md
```

## Quick Start

### One-Click Startup

From the project root:

```powershell
.\start-dev.ps1
```

This opens two PowerShell windows: one for the FastAPI backend and one for the Vite frontend.

### Backend

```powershell
cd backend
uv venv --python 3.12
.\.venv\Scripts\activate
uv sync
uv run uvicorn app.main:app --reload
```

### Frontend

```powershell
cd frontend
pnpm install
pnpm dev
```

## Next Milestone

The next implementation milestone is to connect:

1. task creation API
2. orchestrator state machine
3. tool adapter abstraction
4. frontend workflow timeline
