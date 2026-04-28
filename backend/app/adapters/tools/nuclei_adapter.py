import json
from pathlib import Path
from subprocess import CompletedProcess

from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    category = "scan"
    command_name = "nuclei"

    def __init__(self, template_path: Path) -> None:
        self.template_path = template_path

    def template_available(self) -> bool:
        return self.template_path.exists()

    def build_args(self, target: str, context=None) -> list[str]:
        profile = self.target_profile(target)
        return [
            self.command_executable(),
            "-u",
            profile.request_url,
            "-jsonl",
            "-t",
            str(self.template_path),
            "-duc",
            "-silent",
            "-nc",
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        available = self.is_available() and self.template_available()
        execution_mode = "native" if available else "simulated"
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale="Run a lightweight nuclei pass to turn recon signals into scan findings.",
            target=target,
            available=available,
            execution_mode=execution_mode,
        )

    def simulate(self, target: str, context=None) -> ToolExecutionResult:
        available = self.is_available() and self.template_available()
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary="Prototype nuclei scan completed in simulated mode with no confirmed findings.",
            evidence=[
                f"template available: {self.template_available()}",
                f"binary available: {self.is_available()}",
            ],
            success=True,
            command=self.render_command(target, context),
            available=available,
            execution_mode="native" if available else "simulated",
        )

    def parse_native_result(
        self,
        *,
        target: str,
        completed: CompletedProcess[str],
        duration_ms: int,
        raw_output_path: str,
    ) -> ToolExecutionResult:
        stdout = completed.stdout.strip()
        evidence = ["No nuclei matches returned by the local template."]
        summary = f"Nuclei completed with return code {completed.returncode}."
        if stdout:
            try:
                payload = json.loads(stdout.splitlines()[0])
                evidence = [
                    f"template: {payload.get('template-id', 'unknown')}",
                    f"matched-at: {payload.get('matched-at', target)}",
                    f"severity: {payload.get('info', {}).get('severity', 'unknown')}",
                ]
                matcher_name = payload.get("matcher-name")
                if matcher_name:
                    evidence.append(f"matcher: {matcher_name}")
                extracted = payload.get("extracted-results") or []
                if extracted:
                    evidence.extend(f"extract: {item}" for item in extracted[:2])
                summary = (
                    f"Nuclei reported template {payload.get('template-id', 'unknown')} against "
                    f"{payload.get('matched-at', target)}."
                )
            except json.JSONDecodeError:
                evidence = stdout.splitlines()[:5]
        success = completed.returncode == 0
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary=summary,
            evidence=evidence,
            success=success,
            command=self.render_command(target),
            available=True,
            execution_mode="native",
            raw_output_path=raw_output_path,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
        )
