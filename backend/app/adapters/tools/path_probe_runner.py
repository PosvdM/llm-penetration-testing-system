from __future__ import annotations

import json
import re
import sys

import httpx

from app.core.targeting import parse_target

DEFAULT_PATHS = (
    "/",
    "/manager/html",
    "/host-manager/html",
    "/docs/",
    "/examples/",
    "/manager/status",
)
INTERESTING_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405}
MAX_PATHS = 8
HTTP_TIMEOUT_SECONDS = 1.0


def _extract_title(body: str) -> str | None:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def _normalize_path(path: str) -> str:
    value = path.strip()
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"


def _dedupe_paths(paths: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for path in paths:
        value = _normalize_path(path)
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    base_url = profile.base_url
    requested_paths: list[str] = []
    if len(argv) >= 3:
        try:
            parsed_paths = json.loads(argv[2])
            if isinstance(parsed_paths, list):
                requested_paths = [str(item) for item in parsed_paths if str(item).strip()]
        except Exception:
            requested_paths = []
    paths_to_check = _dedupe_paths([*requested_paths, *DEFAULT_PATHS])[:MAX_PATHS]
    checked: list[dict[str, object]] = []
    interesting: list[dict[str, object]] = []

    with httpx.Client(
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=False,
        verify=False,
        trust_env=False,
    ) as client:
        for path in paths_to_check:
            url = f"{base_url}{path}"
            entry: dict[str, object] = {"path": path, "url": url}
            try:
                response = client.get(url)
                entry["status_code"] = response.status_code
                title = _extract_title(response.text)
                if title:
                    entry["title"] = title
                location = response.headers.get("location")
                if location:
                    entry["location"] = location
                server = response.headers.get("server")
                if server:
                    entry["server"] = server
            except Exception as exc:
                entry["error"] = str(exc)
            checked.append(entry)

            status_code = entry.get("status_code")
            if isinstance(status_code, int) and status_code in INTERESTING_STATUS_CODES:
                interesting.append(entry)

    print(
        json.dumps(
            {
                "base_url": base_url,
                "requested_paths": _dedupe_paths(requested_paths)[:MAX_PATHS],
                "checked": checked,
                "interesting": interesting,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
