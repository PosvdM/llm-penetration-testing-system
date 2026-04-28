import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class CommandProbeAdapter(ToolAdapter):
    name = "command_probe"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.command_probe_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Probe suspicious same-origin query parameters with a low-impact canary so the workflow can "
                "confirm obvious command-execution behavior instead of stopping at surface discovery."
            ),
            target=target,
            available=self.is_available(),
            execution_mode=self.execution_mode(),
        )

    def simulate(self, target: str, context=None) -> ToolExecutionResult:
        availability = self.is_available()
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary="Prototype command probe did not confirm execution, but found a suspicious query parameter.",
            evidence=[
                "candidate: /index.php?cmd=id | parameter: cmd | source: body-text",
                "no confirmed command execution indicator from current candidate set",
                f"binary available: {availability}",
            ],
            success=True,
            command=self.render_command(target, context),
            available=availability,
            execution_mode=self.execution_mode(),
        )

    def parse_native_result(
        self,
        *,
        target: str,
        completed,
        duration_ms: int,
        raw_output_path: str,
    ) -> ToolExecutionResult:
        stdout = completed.stdout.strip()
        evidence = ["No suspicious command-style query parameters were confirmed from the current page set."]
        summary = f"Command probe completed with return code {completed.returncode}."

        if stdout:
            try:
                payload = json.loads(stdout)
                candidates = payload.get("candidates", [])
                confirmed = payload.get("confirmed", [])
                evidence = []

                root = payload.get("root", {})
                if root.get("status_code") is not None:
                    evidence.append(f"root: {payload.get('request_url', target)} -> {root['status_code']}")

                for item in candidates[:3]:
                    evidence.append(
                        f"candidate: {item.get('path', '/')}?{item.get('parameter')}={item.get('original_value', '')} "
                        f"| parameter: {item.get('parameter')} | source: {item.get('source', 'unknown')}"
                    )

                for item in confirmed[:2]:
                    evidence.append(
                        f"confirmed: {item.get('path', '/')} | parameter: {item.get('parameter')} "
                        f"| marker: {item.get('marker')} | status: {item.get('status_code', 'unknown')}"
                    )

                if confirmed:
                    summary = (
                        f"Command probe confirmed {len(confirmed)} command-execution indicator(s) under "
                        f"{payload.get('base_url', target)}."
                    )
                elif candidates:
                    summary = (
                        f"Command probe identified {len(candidates)} suspicious command-style parameter target(s) "
                        f"under {payload.get('base_url', target)} but did not confirm execution."
                    )
                    evidence.append("no confirmed command execution indicator from current candidate set")
                elif payload.get("error"):
                    summary = f"Command probe failed while inspecting {payload.get('base_url', target)}."
                    evidence = [f"error: {payload['error']}"]
                else:
                    summary = (
                        f"Command probe reached {payload.get('base_url', target)} but did not identify suspicious "
                        "command-style query parameters."
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
