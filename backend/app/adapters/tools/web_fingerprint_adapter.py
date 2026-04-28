import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class WebFingerprintAdapter(ToolAdapter):
    name = "web_fingerprint"
    category = "recon"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.web_fingerprint_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Collect reproducible HTTP headers, title, and lightweight stack hints without relying on "
                "an external fingerprinting binary."
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
            summary="Prototype web fingerprinting suggests an Apache Tomcat stack.",
            evidence=[
                "status_code: 200",
                "title: Apache Tomcat/8.5.x",
                "header: server=Apache-Coyote/1.1",
                "tech: tomcat, servlet",
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
        evidence = ["No web fingerprint captured"]
        summary = f"Web fingerprinting completed with return code {completed.returncode}."
        if stdout:
            try:
                payload = json.loads(stdout)
                if payload.get("error"):
                    evidence = [f"error: {payload['error']}"]
                else:
                    evidence = [
                        f"url: {payload.get('final_url', payload.get('url', target))}",
                        f"status_code: {payload.get('status_code', 'unknown')}",
                    ]
                    if payload.get("title"):
                        evidence.append(f"title: {payload['title']}")
                    for key, value in (payload.get("headers") or {}).items():
                        evidence.append(f"header: {key}={value}")
                    technologies = payload.get("technologies") or []
                    if technologies:
                        evidence.append(f"tech: {', '.join(technologies)}")
                    summary = (
                        f"Web fingerprinting collected stack hints for "
                        f"{payload.get('final_url', payload.get('url', target))}."
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
