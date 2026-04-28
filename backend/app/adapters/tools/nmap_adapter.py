from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class NmapAdapter(ToolAdapter):
    name = "nmap"
    category = "recon"
    command_name = "nmap"

    def build_args(self, target: str, context=None) -> list[str]:
        profile = self.target_profile(target)
        args = [self.command_executable(), "-sV", "-Pn"]
        if profile.port is not None:
            args.extend(["-p", str(profile.port)])
        args.append(profile.host)
        return args

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale="Profile exposed ports and basic service banners before analysis.",
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
            summary="Prototype recon suggests an HTTP service exposed on port 8080.",
            evidence=[
                "tcp/8080 open http Apache Tomcat",
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
        first_signal = next((line.strip() for line in stdout.splitlines() if "/tcp" in line), "No open ports detected")
        success = completed.returncode == 0
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary=f"Nmap completed with return code {completed.returncode}.",
            evidence=[first_signal],
            success=success,
            command=self.render_command(target),
            available=True,
            execution_mode="native",
            raw_output_path=raw_output_path,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
        )
