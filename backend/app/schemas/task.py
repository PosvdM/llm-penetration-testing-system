from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.orchestrator.states import TaskStatus
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


def utc_now() -> datetime:
    return datetime.now(UTC)


class TimelineEvent(BaseModel):
    event_id: str
    title: str
    status: Literal["done", "active", "pending"]
    phase: TaskStatus
    detail: str
    created_at: datetime = Field(default_factory=utc_now)


class TaskCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Authorized target URL or host")
    scenario: str = Field(..., min_length=1, description="Lab scenario or challenge name")


class TaskSummary(BaseModel):
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Authorized test target")
    scenario: str = Field(..., description="Scenario or lab type")
    status: TaskStatus = Field(..., description="Current workflow status")
    current_phase: str = Field(..., description="Human-readable phase label")
    is_running: bool = Field(False, description="Whether an automated workflow is currently running")
    created_at: datetime = Field(default_factory=utc_now, description="Task creation timestamp")


class LLMStrategyPlan(BaseModel):
    summary: str
    priority: Literal["low", "medium", "high"]
    recommended_tools: list[str] = Field(default_factory=list)
    focus_areas: list[str] = Field(default_factory=list)
    priority_paths: list[str] = Field(default_factory=list)
    verification_goals: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    rationale: str


class VerifiedFinding(BaseModel):
    finding_id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    source_tool: str
    affected_asset: str | None = None
    confidence: Literal["low", "medium", "high"] = "medium"
    summary: str
    impact: str | None = None
    evidence: list[str]
    artifact_paths: list[str] = Field(default_factory=list)
    remediation: str
    next_steps: list[str] = Field(default_factory=list)
    verification_status: Literal["verified", "informational", "rejected"]


class ReportArtifact(BaseModel):
    report_id: str
    title: str
    summary: str
    report_path: str
    generated_at: datetime = Field(default_factory=utc_now)


class TaskDetail(TaskSummary):
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    progress_current: int = Field(..., ge=0, description="Current progress step")
    progress_total: int = Field(..., ge=1, description="Total progress steps")
    timeline: list[TimelineEvent]
    planned_tools: list[ToolExecutionPlan] = Field(default_factory=list)
    tool_results: list[ToolExecutionResult] = Field(default_factory=list)
    analysis_summary: str | None = None
    llm_strategy_plan: LLMStrategyPlan | None = None
    verification_summary: str | None = None
    verified_findings: list[VerifiedFinding] = Field(default_factory=list)
    report_artifact: ReportArtifact | None = None
    latest_result: ToolExecutionResult | None = None
    last_error: str | None = None


class TaskAdvanceResponse(BaseModel):
    task: TaskDetail
    advanced: bool


class TaskStartResponse(BaseModel):
    task: TaskDetail
    started: bool


class ReportPreviewResponse(BaseModel):
    task_id: str
    report_path: str
    content: str
