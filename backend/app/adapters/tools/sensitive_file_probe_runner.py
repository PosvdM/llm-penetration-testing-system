from __future__ import annotations

import json
import sys

import httpx

from app.core.targeting import parse_target

HTTP_TIMEOUT_SECONDS = 3.0
COMMON_PATHS = (
    "/.env",
    "/.git/config",
    "/config.php.bak",
    "/config.php.save",
    "/backup.zip",
    "/db.sql",
    "/phpinfo.php",
)
CONTENT_MARKERS = {
    "/.env": ("db_password", "app_key", "secret_key", "mysql"),
    "/.git/config": ("[core]", "repositoryformatversion"),
    "/config.php.bak": ("<?php", "$", "password", "mysqli"),
    "/config.php.save": ("<?php", "$", "password", "mysqli"),
    "/db.sql": ("create table", "insert into"),
    "/phpinfo.php": ("php version", "php credits", "configuration"),
}


def _looks_sensitive(path: str, body: str) -> bool:
    lowered = body.lower()
    markers = CONTENT_MARKERS.get(path, ())
    return any(marker in lowered for marker in markers)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    base_url = profile.base_url

    payload: dict[str, object] = {
        "base_url": base_url,
        "checked": [],
        "confirmed": [],
    }

    try:
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            verify=False,
            trust_env=False,
        ) as client:
            confirmed: list[dict[str, object]] = []
            checked: list[dict[str, object]] = []
            for path in COMMON_PATHS:
                url = f"{base_url}{path}"
                entry: dict[str, object] = {"path": path, "url": url}
                try:
                    response = client.get(url)
                    entry["status_code"] = response.status_code
                    checked.append(entry)
                    if response.status_code == 200 and _looks_sensitive(path, response.text):
                        confirmed.append(
                            {
                                "path": path,
                                "status_code": response.status_code,
                                "content_hint": "sensitive content markers detected",
                            }
                        )
                except Exception as exc:
                    entry["error"] = str(exc)
                    checked.append(entry)
            payload["checked"] = checked
            payload["confirmed"] = confirmed
    except Exception as exc:
        payload["error"] = str(exc)
        print(json.dumps(payload, ensure_ascii=False))
        return 1

    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
