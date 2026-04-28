from pathlib import Path

from app.adapters.tools.base import ToolAdapter
from app.adapters.tools.command_probe_adapter import CommandProbeAdapter
from app.adapters.tools.heartbleed_probe_adapter import HeartbleedProbeAdapter
from app.adapters.tools.httpx_adapter import HttpxAdapter
from app.adapters.tools.input_surface_adapter import InputSurfaceAdapter
from app.adapters.tools.login_sqli_probe_adapter import LoginSQLiProbeAdapter
from app.adapters.tools.nmap_adapter import NmapAdapter
from app.adapters.tools.nuclei_adapter import NucleiAdapter
from app.adapters.tools.param_injection_probe_adapter import ParamInjectionProbeAdapter
from app.adapters.tools.path_probe_adapter import PathProbeAdapter
from app.adapters.tools.sensitive_file_probe_adapter import SensitiveFileProbeAdapter
from app.adapters.tools.web_fingerprint_adapter import WebFingerprintAdapter
from app.core.paths import BACKEND_DIR


def get_recon_adapters() -> list[ToolAdapter]:
    return [
        NmapAdapter(),
        HttpxAdapter(),
        WebFingerprintAdapter(),
    ]


def get_scan_adapters() -> list[ToolAdapter]:
    template_path = BACKEND_DIR / "app" / "assets" / "nuclei" / "local-http-fingerprint.yaml"
    return [
        PathProbeAdapter(),
        InputSurfaceAdapter(),
        ParamInjectionProbeAdapter(),
        CommandProbeAdapter(),
        LoginSQLiProbeAdapter(),
        SensitiveFileProbeAdapter(),
        HeartbleedProbeAdapter(),
        NucleiAdapter(Path(template_path)),
    ]
