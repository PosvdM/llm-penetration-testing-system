# LLM Penetration Testing System Project Plan

> 历史规划，包含尚未实现的设计，不代表当前功能。当前说明见[项目首页](../../README.md)与[架构文档](../architecture/OVERVIEW.md)。

## 1. Project Positioning

This project aims to build an automated penetration testing system driven by large language models for authorized lab, teaching, research, and competition scenarios.

The system should demonstrate a complete closed loop:

1. target analysis
2. attack surface discovery
3. vulnerability hypothesis generation
4. tool execution and exploit attempt
5. result verification
6. evidence collection
7. report generation

For the competition, the first priority is not "cover every tool", but "stably complete one end-to-end demonstration with clear evidence, reproducibility, and visible reasoning from the LLM".

## 2. Target Outcomes

### 2.1 MVP Goal

Build a version that can, on one authorized target or one standard vulnerable lab scenario, automatically complete:

- basic fingerprinting
- strategy planning
- vulnerability detection
- exploit validation
- evidence output
- structured report generation

Recommended first scenarios:

- Vulhub `struts2/s2-045`
- Vulhub `thinkphp/5.0.23-rce`
- Vulhub `tomcat/CVE-2017-12615`

### 2.2 Competition Goal

On top of the MVP, further improve:

- Linux and Windows target recognition
- support for more integrated security tools
- support for multi-stage attack chains
- clearer process visualization
- richer reporting with remediation suggestions

## 3. Overall Architecture

The recommended architecture is:

1. Presentation Layer
2. Orchestration Layer
3. LLM Decision Layer
4. Tool Adapter Layer
5. Evidence and Data Layer
6. Reporting Layer

### 3.1 Architecture Responsibilities

#### Presentation Layer

Used for:

- creating tasks
- selecting models
- viewing live task progress
- browsing evidence and logs
- downloading reports

Recommended form:

- backend API + frontend dashboard

#### Orchestration Layer

This is the system core. It manages:

- workflow states
- task sequencing
- retry logic
- timeout control
- stop conditions
- branching and fallback logic

Recommended workflow states:

- `PENDING`
- `RECON`
- `ANALYSIS`
- `SCAN`
- `VERIFY`
- `POST_VERIFY`
- `REPORTING`
- `COMPLETED`
- `FAILED`

#### LLM Decision Layer

This layer is responsible for:

- understanding target context
- generating testing plans
- selecting tools
- interpreting intermediate results
- deciding next actions
- summarizing findings
- producing human-readable explanations

To make the LLM contribution visible in the competition, this layer should output structured decisions such as:

- selected next action
- reason for selection
- required tool parameters
- expected signal
- confidence score

#### Tool Adapter Layer

This layer wraps external tools into a unified interface. Each adapter should define:

- input schema
- command template
- timeout policy
- parser
- normalized output schema
- error mapping

Target integrated tools can include:

- `nmap`
- `whatweb`
- `httpx`
- `nuclei`
- `nikto`
- `gobuster`
- `dirsearch`
- `sqlmap`
- `hydra`
- `wpscan`
- `ffuf`
- `metasploit`
- `searchsploit`

#### Evidence and Data Layer

Used to store:

- raw tool outputs
- normalized findings
- screenshots
- HTTP requests and responses
- shell command logs
- execution traces
- vulnerability verification evidence
- generated reports

This layer is critical because the competition explicitly values reproducibility and traceability.

#### Reporting Layer

Generates:

- basic penetration report
- detailed report
- remediation suggestions
- execution timeline
- evidence appendix

## 4. Recommended Multi-Agent Design

The competition explicitly encourages modular or agent-based design. A practical agent split is:

1. `Planner Agent`
   Responsible for decomposing the task and deciding the current testing phase.

2. `Recon Agent`
   Responsible for fingerprinting, service discovery, and initial attack surface collection.

3. `Vuln Analyst Agent`
   Responsible for mapping target features to likely vulnerability categories and selecting relevant tools.

4. `Executor Agent`
   Responsible for invoking tools and exploit steps through adapters.

5. `Verifier Agent`
   Responsible for checking whether a vulnerability is genuinely exploitable and whether evidence is sufficient.

6. `Reporter Agent`
   Responsible for summarizing the process and generating the final structured report.

### 4.1 Suggested Collaboration Pattern

- Orchestrator assigns the current phase.
- Planner produces the next action candidates.
- Relevant execution agent runs the selected tool.
- Verifier decides whether the result is valid.
- Reporter continuously updates the evidence record.

This design is easier to explain during defense than a single opaque agent.

## 5. Recommended Technical Stack

## 5.1 Backend

Recommended:

- `Python 3.11+`
- `FastAPI`
- `Pydantic`
- `SQLAlchemy`
- `Celery` or `RQ` for async tasks if needed

Reason:

- Python is ideal for integrating security tools, parsing outputs, and calling LLM APIs.
- FastAPI makes it easy to build APIs and demo backends quickly.
- Pydantic is useful for normalizing structured data between agents and tools.

## 5.2 Frontend

Recommended:

- `React`
- `Vite`
- `TypeScript`
- `Tailwind CSS` or `Ant Design`

Core pages:

- task creation page
- real-time workflow page
- evidence and report page
- system settings page

If time is tight, a lightweight dashboard is enough. The key is to make the testing flow visible.

## 5.3 Storage

Recommended:

- `PostgreSQL` or `SQLite` for structured metadata
- local file storage for evidence artifacts

Suggested split:

- database stores tasks, phases, findings, reports metadata
- file storage stores raw outputs, screenshots, JSON artifacts, HTML reports

## 5.4 LLM Access

The system should abstract model providers behind one interface:

- `OpenAI`
- `Anthropic`
- `DeepSeek`

Suggested interface methods:

- `plan_next_step(context)`
- `analyze_scan_result(context)`
- `decide_verification_path(context)`
- `summarize_report(context)`

This aligns with the competition requirement to support mainstream model interfaces.

## 5.5 Security Tool Integration Strategy

Do not integrate dozens of tools at once. Use three waves:

### Wave 1: MVP Tools

- `nmap`
- `httpx`
- `whatweb`
- `nuclei`
- `sqlmap`
- `gobuster`

### Wave 2: Common Web Expansion

- `nikto`
- `ffuf`
- `wpscan`
- `hydra`
- `searchsploit`

### Wave 3: Advanced Validation

- `metasploit`
- custom PoC runner
- post-exploitation script runner

## 6. Core Data Model

At minimum, define the following entities:

### 6.1 Task

- task_id
- target
- scenario_type
- status
- selected_model
- start_time
- end_time

### 6.2 PhaseRecord

- phase_name
- start_time
- end_time
- input_summary
- output_summary
- decision_reason

### 6.3 ToolExecution

- tool_name
- command
- parameters
- raw_output_path
- parsed_output
- exit_code
- duration_ms

### 6.4 Finding

- finding_id
- title
- category
- severity
- evidence_refs
- validation_status
- remediation

### 6.5 Report

- report_id
- task_id
- report_type
- generated_at
- report_path

## 7. Recommended Directory Structure

```text
llm-pentest-system/
├─ backend/
│  ├─ app/
│  │  ├─ api/
│  │  ├─ core/
│  │  ├─ agents/
│  │  ├─ orchestrator/
│  │  ├─ adapters/
│  │  │  ├─ llm/
│  │  │  └─ tools/
│  │  ├─ models/
│  │  ├─ schemas/
│  │  ├─ services/
│  │  ├─ repositories/
│  │  └─ reports/
│  ├─ tests/
│  └─ requirements.txt
├─ frontend/
│  ├─ src/
│  │  ├─ pages/
│  │  ├─ components/
│  │  ├─ services/
│  │  ├─ hooks/
│  │  └─ types/
│  └─ package.json
├─ data/
│  ├─ tasks/
│  ├─ evidence/
│  ├─ raw/
│  └─ reports/
├─ docs/
│  ├─ architecture/
│  ├─ demo/
│  ├─ setup/
│  └─ competition/
├─ scripts/
│  ├─ init_env/
│  ├─ run_demo/
│  └─ import_targets/
├─ docker/
├─ .env.example
└─ README.md
```

## 8. Suggested API Scope

Recommended first backend APIs:

- `POST /tasks`
- `GET /tasks`
- `GET /tasks/{id}`
- `POST /tasks/{id}/start`
- `POST /tasks/{id}/stop`
- `GET /tasks/{id}/timeline`
- `GET /tasks/{id}/findings`
- `GET /tasks/{id}/report`
- `GET /tools`
- `GET /models`

## 9. Suggested MVP Workflow

The first end-to-end workflow should be:

1. input target and scenario
2. perform fingerprinting using `nmap`, `httpx`, `whatweb`
3. let the LLM summarize likely attack paths
4. invoke one or more tools such as `nuclei`, `gobuster`, `sqlmap`
5. normalize results
6. let the LLM choose whether verification is needed
7. run validation or exploit attempt
8. store evidence
9. generate structured report

### 9.1 MVP Success Criteria

- one lab can be tested from start to finish without manual intervention
- tool outputs are stored and traceable
- at least one verified finding is produced
- a downloadable report is generated
- the UI can show each workflow step and current status

## 10. Development Milestones

## Week 1: Requirement Freeze and Skeleton

Goals:

- finalize architecture
- define workflow states
- define normalized schemas
- create backend and frontend project skeleton

Deliverables:

- architecture diagram
- module responsibility document
- repository skeleton
- environment setup guide draft

## Week 2: Orchestrator and Tool Adapter Base

Goals:

- implement task model
- implement workflow engine or state machine
- implement a unified tool adapter interface
- complete first adapters for `nmap`, `httpx`, `whatweb`

Deliverables:

- task orchestration prototype
- first normalized execution records
- basic task timeline view

## Week 3: LLM Planning and Decision Core

Goals:

- implement model provider abstraction
- build prompts for planning and result interpretation
- connect LLM output to orchestration decisions

Deliverables:

- planner agent prototype
- reasoning trace examples
- configurable model switching

## Week 4: Vulnerability Scan and Verification

Goals:

- integrate `nuclei`, `gobuster`, `sqlmap`
- implement finding normalization
- implement verification rules

Deliverables:

- first complete automated scan pipeline
- verified finding examples
- evidence storage prototype

## Week 5: Reporting and Visualization

Goals:

- generate structured reports
- improve timeline and evidence UI
- support report export

Deliverables:

- HTML or PDF report
- evidence panel
- complete demo workflow UI

## Week 6: Demo Hardening

Goals:

- optimize reliability
- add retries and failure fallback
- polish demo scripts
- prepare competition documentation

Deliverables:

- stable demo scenario
- installation guide
- teaching guide
- demo recording script

## Week 7+: Expansion Phase

Optional if time allows:

- support Windows target strategies
- support multi-stage attack paths
- integrate more tools
- improve remediation intelligence

## 11. Competition Material Checklist

The competition submission package should be prepared in parallel with development.

Required items to maintain from the beginning:

- project overview
- project introduction PPT
- detailed solution document
- demo video
- system architecture diagram
- module design description
- installation guide
- teaching document
- team worklog and process document
- public reproducible demo environment

To reduce late-stage pressure, create these folders early:

- `docs/competition`
- `docs/setup`
- `docs/demo`

## 12. Demo Strategy

For competition presentation, do not try to show everything. Show one clean and successful story:

1. choose one simple but representative target
2. show task creation
3. show automated workflow progression
4. show at least one verified vulnerability
5. show the evidence chain
6. show the generated report and remediation suggestion

The judges should clearly see:

- where the LLM made decisions
- where tools were executed
- how results were verified
- how the final report was formed

## 13. Main Risks and Mitigations

### Risk 1: Tool Pileup Without Workflow Discipline

Mitigation:

- define a unified adapter interface first
- onboard tools in waves

### Risk 2: LLM Becomes a Cosmetic Wrapper

Mitigation:

- force LLM outputs to include explicit decisions
- record action reason, confidence, and next step

### Risk 3: High False Positive Rate

Mitigation:

- add verification phase
- separate scan findings from verified findings

### Risk 4: Demo Instability

Mitigation:

- fix the demo environment early
- prepare deterministic sample targets
- record expected outputs

### Risk 5: Materials Prepared Too Late

Mitigation:

- update docs during development
- store screenshots and evidence as you build

## 14. Recommended Implementation Priority

If the team has limited time, use this order:

1. workflow engine
2. tool adapter standard
3. recon tools
4. LLM planning and interpretation
5. verification logic
6. report generation
7. visualization
8. tool expansion
9. multi-stage attacks

## 15. Immediate Next Actions

The next concrete steps should be:

1. initialize the repository structure
2. choose the backend and frontend stack
3. define core schemas for task, tool execution, finding, and report
4. choose one Vulhub target as the MVP scenario
5. implement the orchestration skeleton
6. integrate the first three recon tools

If execution starts immediately, the best first milestone is:

"Run one target from fingerprinting to a generated report with a visible workflow timeline."
