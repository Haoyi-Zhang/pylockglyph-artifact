"""Deterministic TOML serializer for replay-generated transformations.

The serializer covers the data shapes present in the included manifests and
lockfiles. It is intentionally small and is used only for temporary controls.
"""
from __future__ import annotations

from datetime import date, datetime, time
from typing import Any


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


def _key(value: str) -> str:
    if value and all(ch.isalnum() or ch in "_-" for ch in value):
        return value
    return _quote(value)


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{_key(str(k))} = {_value(v)}" for k, v in value.items() if v is not None) + " }"
    if value is None:
        raise TypeError("None is not serializable")
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def dumps(document: dict[str, Any]) -> str:
    lines: list[str] = []

    def emit_table(path: tuple[str, ...], table: dict[str, Any], *, array_item: bool = False) -> None:
        scalar_items: list[tuple[str, Any]] = []
        nested_tables: list[tuple[str, dict[str, Any]]] = []
        arrays_of_tables: list[tuple[str, list[dict[str, Any]]]] = []
        for key, value in table.items():
            if value is None:
                continue
            if isinstance(value, dict) and not array_item:
                nested_tables.append((str(key), value))
            elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value) and not array_item:
                arrays_of_tables.append((str(key), value))
            else:
                scalar_items.append((str(key), value))
        if path:
            lines.append(("[[" if array_item else "[") + ".".join(_key(part) for part in path) + ("]]" if array_item else "]"))
        for key, value in scalar_items:
            lines.append(f"{_key(key)} = {_value(value)}")
        if path or scalar_items:
            lines.append("")
        for key, nested in nested_tables:
            emit_table(path + (key,), nested)
        for key, items in arrays_of_tables:
            for item in items:
                emit_table(path + (key,), item, array_item=True)

    emit_table((), document)
    return "\n".join(lines).rstrip() + "\n"
