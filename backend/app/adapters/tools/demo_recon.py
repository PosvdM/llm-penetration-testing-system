from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class DemoReconAdapter(ToolAdapter):
    name = "demo-recon"
    category = "recon"
    command_name = "demo-recon"

    def build_args(self, target: str, context=None) -> list[str]:
        return ["demo-recon", target]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale="Run a basic service discovery pass before deeper analysis.",
            target=target,
            available=False,
            execution_mode="simulated",
        )

    def simulate(self, target: str, context=None) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary="Simulated recon identified HTTP service on port 8080.",
            evidence=[
                "tcp/8080 open http Apache Tomcat",
                "Fingerprint confidence: high",
            ],
            success=True,
            command=self.render_command(target, context),
            available=False,
            execution_mode="simulated",
        )

    def parse_native_result(self, *, target: str, completed, duration_ms: int, raw_output_path: str) -> ToolExecutionResult:
        raise NotImplementedError("DemoReconAdapter does not support native execution.")
