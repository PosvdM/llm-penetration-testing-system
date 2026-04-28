from typing import Literal

from pydantic import BaseModel, Field


class ToolExecutionPlan(BaseModel):
    tool_name: str = Field(..., description="Normalized tool identifier")
    category: str = Field(..., description="Tool category such as recon or scan")
    command: str = Field(..., description="Command template or invocation summary")
    rationale: str = Field(..., description="Why the tool is selected")
    target: str = Field(..., description="Authorized target")
    available: bool = Field(..., description="Whether the tool binary is available locally")
    execution_mode: Literal["native", "simulated"] = Field(
        ..., description="How the adapter will behave in the prototype"
    )


class ToolExecutionResult(BaseModel):
    tool_name: str
    category: str
    target: str
    summary: str
    evidence: list[str]
    success: bool
    command: str
    available: bool
    execution_mode: Literal["native", "simulated"]
    raw_output_path: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
