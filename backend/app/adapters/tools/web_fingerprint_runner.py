from __future__ import annotations

import json
import re
import sys

import httpx

from app.core.targeting import parse_target


def _extract_title(body: str) -> str | None:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


def _detect_stack(headers: httpx.Headers, body: str) -> list[str]:
    haystack = " ".join(
        [
            headers.get("server", ""),
            headers.get("x-powered-by", ""),
            body[:2000],
        ]
    ).lower()
    stacks: list[str] = []
    markers = {
        "tomcat": ("tomcat", "apache-coyote", "servlet"),
        "nginx": ("nginx",),
        "apache": ("apache", "httpd"),
        "struts": ("struts",),
    }
    for label, values in markers.items():
        if any(value in haystack for value in values):
            stacks.append(label)
    return stacks


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    url = profile.request_url

    payload: dict[str, object] = {"url": url}
    try:
        with httpx.Client(timeout=4.0, follow_redirects=True, verify=False, trust_env=False) as client:
            response = client.get(url)
        payload["status_code"] = response.status_code
        payload["final_url"] = str(response.url)
        title = _extract_title(response.text)
        if title:
            payload["title"] = title
        headers = {}
        for key in ("server", "x-powered-by", "content-type"):
            value = response.headers.get(key)
            if value:
                headers[key] = value
        if headers:
            payload["headers"] = headers
        technologies = _detect_stack(response.headers, response.text)
        if technologies:
            payload["technologies"] = technologies
    except Exception as exc:
        payload["error"] = str(exc)

    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
