from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class TargetProfile:
    raw: str
    host: str
    port: int | None
    scheme: str | None
    path: str
    query: str

    @property
    def is_web_target(self) -> bool:
        return self.scheme is not None or self.port is not None or self.path not in {"", "/"}

    @property
    def inferred_scheme(self) -> str:
        if self.scheme:
            return self.scheme
        if self.port in {443, 8443}:
            return "https"
        return "http"

    @property
    def host_with_port(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        return f"{self.inferred_scheme}://{self.host_with_port}"

    @property
    def request_url(self) -> str:
        path = self.path or ""
        query = f"?{self.query}" if self.query else ""
        if not path or path == "/":
            return f"{self.base_url}{query}"
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{normalized_path}{query}"


def parse_target(raw_target: str) -> TargetProfile:
    value = raw_target.strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or parsed.path or value
    path = parsed.path if parsed.hostname else ""
    query = parsed.query if parsed.hostname else ""
    scheme = parsed.scheme or None
    return TargetProfile(
        raw=value,
        host=host,
        port=parsed.port,
        scheme=scheme,
        path=path,
        query=query,
    )
