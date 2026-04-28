from datetime import UTC, datetime
from uuid import uuid4

from app.core.paths import REPORT_OUTPUT_DIR, ensure_data_dirs
from app.orchestrator.states import TaskStatus
from app.schemas.task import ReportArtifact, TaskDetail, VerifiedFinding


def _now_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _render_findings(findings: list[VerifiedFinding]) -> str:
    if not findings:
        return "No verified findings were produced by the current workflow.\n"

    sections = []
    for finding in findings:
        lines = [
            f"### {finding.title}",
            f"- Severity: {finding.severity}",
            f"- Confidence: {finding.confidence}",
            f"- Source Tool: {finding.source_tool}",
            f"- Status: {finding.verification_status}",
            f"- Asset: {finding.affected_asset or 'n/a'}",
            f"- Summary: {finding.summary}",
            f"- Impact: {finding.impact or 'n/a'}",
            f"- Remediation: {finding.remediation}",
            "- Evidence:",
            *[f"  - {item}" for item in finding.evidence],
        ]
        if finding.next_steps:
            lines.extend(["- Next Steps:", *[f"  - {item}" for item in finding.next_steps]])
        if finding.artifact_paths:
            lines.extend(["- Artifacts:", *[f"  - {item}" for item in finding.artifact_paths]])
        sections.append(
            "\n".join(lines)
        )
    return "\n\n".join(sections) + "\n"


def _render_finding_overview(findings: list[VerifiedFinding]) -> list[str]:
    verified_count = sum(1 for finding in findings if finding.verification_status == "verified")
    informational_count = sum(
        1 for finding in findings if finding.verification_status == "informational"
    )
    rejected_count = sum(1 for finding in findings if finding.verification_status == "rejected")
    severities = ("critical", "high", "medium", "low", "info")
    severity_counts = {
        severity: sum(1 for finding in findings if finding.severity == severity) for severity in severities
    }
    return [
        "## Finding Overview",
        f"- Total Findings: {len(findings)}",
        f"- Verified Findings: {verified_count}",
        f"- Informational Findings: {informational_count}",
        f"- Rejected Leads: {rejected_count}",
        *[f"- Severity {severity.title()}: {severity_counts[severity]}" for severity in severities],
    ]


def _render_tool_execution_summary(task: TaskDetail) -> list[str]:
    lines = ["## Tool Execution Summary"]
    if not task.tool_results:
        lines.append("- No tool executions were recorded.")
        return lines

    for result in task.tool_results:
        lines.append(
            (
                f"- {result.tool_name}: success={result.success} | mode={result.execution_mode} | "
                f"exit_code={result.exit_code if result.exit_code is not None else 'n/a'} | "
                f"duration_ms={result.duration_ms if result.duration_ms is not None else 'n/a'}"
            )
        )
    return lines


def _render_strategy_plan(task: TaskDetail) -> list[str]:
    if task.llm_strategy_plan is None:
        return ["## LLM Strategy Plan", "No structured LLM strategy plan was recorded."]

    plan = task.llm_strategy_plan
    lines = [
        "## LLM Strategy Plan",
        f"- Summary: {plan.summary}",
        f"- Priority: {plan.priority}",
        f"- Recommended Tools: {', '.join(plan.recommended_tools) or 'none'}",
        f"- Rationale: {plan.rationale}",
    ]
    if plan.focus_areas:
        lines.extend(["- Focus Areas:", *[f"  - {item}" for item in plan.focus_areas]])
    if plan.priority_paths:
        lines.extend(["- Priority Paths:", *[f"  - {item}" for item in plan.priority_paths]])
    if plan.verification_goals:
        lines.extend(["- Verification Goals:", *[f"  - {item}" for item in plan.verification_goals]])
    if plan.stop_conditions:
        lines.extend(["- Stop Conditions:", *[f"  - {item}" for item in plan.stop_conditions]])
    return lines


def write_report(task: TaskDetail, executive_summary: str) -> ReportArtifact:
    ensure_data_dirs()
    task_report_dir = REPORT_OUTPUT_DIR / task.task_id
    task_report_dir.mkdir(parents=True, exist_ok=True)

    report_path = task_report_dir / f"{_now_slug()}-report.md"
    final_status = TaskStatus.COMPLETED if task.status == TaskStatus.REPORTING else task.status
    report_contents = "\n".join(
        [
            f"# {task.scenario}",
            "",
            "## Executive Summary",
            executive_summary,
            "",
            "## Target",
            f"- Target: {task.target}",
            f"- Final Status: {final_status}",
            "",
            "## LLM Analysis",
            task.analysis_summary or "No analysis summary available.",
            "",
            *_render_strategy_plan(task),
            "",
            "## Verification",
            task.verification_summary or "No verification summary available.",
            "",
            *_render_finding_overview(task.verified_findings),
            "",
            *_render_tool_execution_summary(task),
            "",
            "## Findings",
            _render_findings(task.verified_findings).rstrip(),
            "",
            "## Evidence Artifacts",
            *[
                f"- {result.tool_name}: {result.raw_output_path or 'no artifact path'}"
                for result in task.tool_results
            ],
        ]
    )
    report_path.write_text(report_contents, encoding="utf-8")

    return ReportArtifact(
        report_id=f"report-{uuid4().hex[:8]}",
        title=f"{task.scenario} Report",
        summary=executive_summary,
        report_path=str(report_path),
    )
