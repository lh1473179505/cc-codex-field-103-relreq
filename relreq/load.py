"""Load exchange snapshots, keys, and policy. Inspect uses this; sign/verify should too."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LoadError(ValueError):
    pass


def _read_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise LoadError(f"cannot read {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise LoadError(f"cannot parse {path}: {e}") from e


def load_exchange(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise LoadError("exchange must be a JSON object")
    if "request" not in data or not isinstance(data["request"], dict):
        raise LoadError("exchange missing request object")
    req = data["request"]
    for key in ("method", "scheme", "authority", "path", "headers", "now"):
        if key not in req:
            raise LoadError(f"request missing {key}")
    for key in ("status", "headers", "now"):
        if key not in data:
            raise LoadError(f"exchange missing {key}")
    if not isinstance(data["headers"], list) or not isinstance(req["headers"], list):
        raise LoadError("headers must be a list of [name, value]")
    req.setdefault("query", "")
    req.setdefault("body", "")
    data.setdefault("body", "")
    data["_source"] = str(path)
    return data


def load_keys(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict) or "keys" not in data or not isinstance(data["keys"], dict):
        raise LoadError("keys file must contain a keys object")
    return data


def load_policy(path: str | Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise LoadError("policy must be a JSON object")
    return data


def signature_header_text(headers: list) -> list[str]:
    out = []
    for name, value in headers or []:
        if isinstance(name, str) and name.lower() == "signature-input":
            out.append(value)
    return out
