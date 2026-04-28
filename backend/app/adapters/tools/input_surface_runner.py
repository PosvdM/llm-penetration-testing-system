from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import httpx

from app.adapters.tools.web_common import (
    extract_forms,
    extract_links,
    extract_title,
    prioritize_links,
)
from app.core.targeting import parse_target

HTTP_TIMEOUT_SECONDS = 2.0
MAX_LINKS = 6
LIKELY_DYNAMIC_KEYWORDS = (
    "login",
    "admin",
    "api",
    "upload",
    "query",
    "search",
    "status",
    "health",
    "debug",
    "tool",
    "panel",
)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    base_url = profile.base_url

    payload: dict[str, object] = {
        "base_url": base_url,
        "root": {},
        "forms": [],
        "links": [],
        "probed": [],
    }

    with httpx.Client(
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=True,
        verify=False,
        trust_env=False,
    ) as client:
        root_response = client.get(base_url)
        root_title = extract_title(root_response.text)
        root_links = extract_links(base_url, root_response.text)
        forms = extract_forms(base_url, root_response.text)

        payload["root"] = {
            "url": str(root_response.request.url),
            "status_code": root_response.status_code,
            "title": root_title,
            "server": root_response.headers.get("server"),
        }
        payload["forms"] = [
            {
                "action": form["action"],
                "method": form["method"],
                "inputs": form["inputs"],
            }
            for form in forms
        ]
        payload["links"] = [urlparse(link).path or "/" for link in root_links[:MAX_LINKS]]

        candidate_links = prioritize_links(
            base_url,
            root_links,
            keywords=LIKELY_DYNAMIC_KEYWORDS,
            max_links=MAX_LINKS,
        )
        probed: list[dict[str, object]] = []
        for link in candidate_links:
            entry: dict[str, object] = {"url": link, "path": urlparse(link).path or "/"}
            try:
                response = client.get(link)
                entry["status_code"] = response.status_code
                title = extract_title(response.text)
                if title:
                    entry["title"] = title
            except Exception as exc:
                entry["error"] = str(exc)
            probed.append(entry)

        payload["probed"] = probed

    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
