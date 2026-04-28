# Architecture Overview

## Initial Skeleton

The current codebase is organized around four main areas:

1. `backend`
   FastAPI service exposing health and task overview APIs.

2. `frontend`
   React and Vite dashboard showing backend status and seed tasks.

3. `data`
   Local storage roots for tasks, evidence, raw outputs, and reports.

4. `docs`
   Project planning, setup guidance, and competition materials.

## Next Architecture Step

The next implementation pass should add:

- orchestrator service
- tool adapter abstraction
- normalized finding model
- task creation and timeline APIs
- report generation pipeline

## Current Execution Model

The prototype now supports:

- task creation and detail APIs
- manual phase advance and automated task start
- recon adapter registry for `nmap`, `httpx`, and `whatweb`
- native execution when the binary exists locally
- simulated execution fallback when the binary is missing
- raw output artifact storage under `data/raw/<task-id>/`

This means the orchestration flow, evidence capture path, and result normalization format are already in place before full tool installation and scan-stage expansion.
