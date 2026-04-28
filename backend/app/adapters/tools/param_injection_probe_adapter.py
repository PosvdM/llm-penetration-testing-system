import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class ParamInjectionProbeAdapter(ToolAdapter):
    name = "param_injection_probe"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.param_injection_probe_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Probe discovered GET/POST parameters with generic error-based and time-based payloads so the "
                "workflow can surface broader injection issues without requiring a CVE-specific signature."
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
            summary="Prototype parameter injection probe found candidate parameters but no confirmed signal.",
            evidence=[
                "candidate: /search.php?q=demo | parameter: q | mode: query",
                "candidate: /doctor.php | parameter: doctorid | mode: form",
                "no confirmed generic parameter injection signal from current candidate set",
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
        evidence = ["No generic parameter injection signals were confirmed from the current candidate set."]
        summary = f"Parameter injection probe completed with return code {completed.returncode}."

        if stdout:
            try:
                payload = json.loads(stdout)
                query_candidates = payload.get("query_candidates", [])
                form_candidates = payload.get("form_candidates", [])
                confirmed = payload.get("confirmed", [])
                evidence = []

                for item in query_candidates[:2]:
                    evidence.append(
                        f"candidate: {item.get('path', '/')}?{item.get('parameter')}={item.get('original_value', '')} "
                        f"| parameter: {item.get('parameter')} | mode: query"
                    )
                for item in form_candidates[:2]:
                    for field in item.get("fields", [])[:2]:
                        evidence.append(
                            f"candidate: {item.get('action', target)} | parameter: {field} | mode: form"
                        )

                for item in confirmed[:3]:
                    evidence.append(
                        f"confirmed: {item.get('mode', 'unknown')} {item.get('path', '/')} | parameter: "
                        f"{item.get('parameter')} | kind: {item.get('kind', 'unknown')} | signal: {item.get('signal', '')}"
                    )

                if confirmed:
                    summary = (
                        f"Parameter injection probe confirmed {len(confirmed)} generic injection indicator(s) under "
                        f"{payload.get('base_url', target)}."
                    )
                elif query_candidates or form_candidates:
                    summary = (
                        f"Parameter injection probe identified candidate parameters under "
                        f"{payload.get('base_url', target)} but did not confirm a signal."
                    )
                    evidence.append("no confirmed generic parameter injection signal from current candidate set")
                elif payload.get("error"):
                    summary = f"Parameter injection probe failed while inspecting {payload.get('base_url', target)}."
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
