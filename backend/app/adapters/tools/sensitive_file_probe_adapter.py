import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class SensitiveFileProbeAdapter(ToolAdapter):
    name = "sensitive_file_probe"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.sensitive_file_probe_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Check a focused set of common sensitive files and backup artifacts so the workflow can "
                "confirm high-value information exposure without depending on product-specific paths."
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
            summary="Prototype sensitive file probe completed without confirmed exposure.",
            evidence=[
                "checked: /.env -> 404",
                "checked: /.git/config -> 403",
                "no confirmed sensitive file exposure from current path set",
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
        evidence = ["No sensitive file exposure was confirmed from the current path set."]
        summary = f"Sensitive file probe completed with return code {completed.returncode}."

        if stdout:
            try:
                payload = json.loads(stdout)
                checked = payload.get("checked", [])
                confirmed = payload.get("confirmed", [])
                evidence = []
                for item in checked[:3]:
                    evidence.append(f"checked: {item.get('path', '/')} -> {item.get('status_code', 'error')}")
                for item in confirmed[:3]:
                    evidence.append(
                        f"confirmed: {item.get('path', '/')} -> {item.get('status_code', 'unknown')} | "
                        f"hint: {item.get('content_hint', '')}"
                    )

                if confirmed:
                    summary = (
                        f"Sensitive file probe confirmed {len(confirmed)} exposure(s) under "
                        f"{payload.get('base_url', target)}."
                    )
                elif checked:
                    summary = (
                        f"Sensitive file probe checked common paths under {payload.get('base_url', target)} "
                        "without confirming exposure."
                    )
                    evidence.append("no confirmed sensitive file exposure from current path set")
                elif payload.get("error"):
                    summary = f"Sensitive file probe failed while inspecting {payload.get('base_url', target)}."
                    evidence = [f"error: {payload['error']}"]
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
