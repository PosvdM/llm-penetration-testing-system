from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class WhatwebAdapter(ToolAdapter):
    name = "whatweb"
    category = "recon"
    command_name = "whatweb"

    def build_args(self, target: str, context=None) -> list[str]:
        profile = self.target_profile(target)
        return [self.command_executable(), profile.request_url]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale="Collect quick application fingerprints that feed later vulnerability hypotheses.",
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
            summary="Prototype fingerprinting suggests Apache Tomcat headers and a JSP-capable stack.",
            evidence=[
                "X-Powered-By: Servlet/4.0",
                "Server: Apache-Coyote/1.1",
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
        first_line = stdout.splitlines()[0].strip() if stdout else "No web fingerprint captured"
        success = completed.returncode == 0
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary=f"WhatWeb completed with return code {completed.returncode}.",
            evidence=[first_line],
            success=success,
            command=self.render_command(target),
            available=True,
            execution_mode="native",
            raw_output_path=raw_output_path,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
        )
