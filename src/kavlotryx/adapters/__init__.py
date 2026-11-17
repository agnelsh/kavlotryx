"""Scanner adapters. Each adapter turns one scanner's output into OCSF records.

Adapters are plug-ins (FR-IN-07): they register under the
``kavlotryx.adapters`` entry-point group. Built-in adapters are also listed
here so that a source checkout works without an installed package.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from kavlotryx.adapters.base import Adapter, AdapterError, ParseResult
from kavlotryx.adapters.ocsf import OcsfAdapter
from kavlotryx.adapters.prowler import ProwlerAdapter
from kavlotryx.adapters.trivy import TrivyAdapter

_BUILTIN: dict[str, type[Adapter]] = {
    "prowler": ProwlerAdapter,
    "trivy": TrivyAdapter,
    "ocsf": OcsfAdapter,
}


def available_adapters() -> dict[str, type[Adapter]]:
    found = dict(_BUILTIN)
    for ep in entry_points(group="kavlotryx.adapters"):
        if ep.name not in found:
            found[ep.name] = ep.load()
    return found


def get_adapter(name: str) -> Adapter:
    adapters = available_adapters()
    try:
        return adapters[name.lower()]()
    except KeyError:
        known = ", ".join(sorted(adapters))
        raise AdapterError(f"unknown scanner {name!r}; known: {known}") from None


__all__ = ["Adapter", "AdapterError", "ParseResult", "available_adapters", "get_adapter"]
