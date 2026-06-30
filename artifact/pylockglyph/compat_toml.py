"""Small TOML compatibility shim for the offline artifact."""
from __future__ import annotations

try:
    import tomllib as _tomllib
except ModuleNotFoundError:  # Python 3.10 replay hosts commonly provide tomli.
    import tomli as _tomllib  # type: ignore[import-not-found]

load = _tomllib.load
loads = _tomllib.loads

__all__ = ["load", "loads"]
