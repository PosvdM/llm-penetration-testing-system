import os
from abc import ABC, abstractmethod
from pathlib import Path
from shutil import which
from subprocess import CompletedProcess
from typing import Any

from app.core.targeting import TargetProfile, parse_target
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult

ToolExecutionContext = dict[str, Any] | None


class ToolAdapter(ABC):
    """Normalized interface for external security tools."""

    name: str
    category: str
    command_name: str
    windows_search_dirs: tuple[str, ...] = ()

    def _common_windows_search_dirs(self) -> list[str]:
        userprofile = os.environ.get("USERPROFILE", "")
        return [
            r"C:\Program Files (x86)\Nmap",
            r"C:\Program Files\Go\bin",
            os.path.join(userprofile, "go", "bin") if userprofile else "",
            *self.windows_search_dirs,
        ]

    def resolve_command(self) -> str | None:
        explicit_path = Path(self.command_name)
        if explicit_path.exists():
            return str(explicit_path)

        resolved = which(self.command_name)
        if resolved:
            return resolved

        for directory in self._common_windows_search_dirs():
            if not directory:
                continue
            for candidate in (
                self.command_name,
                f"{self.command_name}.exe",
                f"{self.command_name}.cmd",
                f"{self.command_name}.bat",
            ):
                command_path = Path(directory) / candidate
                if command_path.exists():
                    return str(command_path)
        return None

    def is_available(self) -> bool:
        return self.resolve_command() is not None

    def execution_mode(self) -> str:
        return "native" if self.is_available() else "simulated"

    def command_executable(self) -> str:
        return self.resolve_command() or self.command_name

    def target_profile(self, target: str) -> TargetProfile:
        return parse_target(target)

    @abstractmethod
    def build_args(self, target: str, context: ToolExecutionContext = None) -> list[str]:
        """Create the subprocess argument list for native execution."""

    def render_command(self, target: str, context: ToolExecutionContext = None) -> str:
        return " ".join(self.build_args(target, context))

    @abstractmethod
    def parse_native_result(
        self,
        *,
        target: str,
        completed: CompletedProcess[str],
        duration_ms: int,
        raw_output_path: str,
    ) -> ToolExecutionResult:
        """Normalize a native tool execution result."""

    @abstractmethod
    def build_plan(self, target: str, context: ToolExecutionContext = None) -> ToolExecutionPlan:
        """Create a normalized plan before execution."""

    @abstractmethod
    def simulate(self, target: str, context: ToolExecutionContext = None) -> ToolExecutionResult:
        """Return a deterministic simulated result for the current prototype."""
