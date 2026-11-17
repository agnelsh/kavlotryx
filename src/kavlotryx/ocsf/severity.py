"""OCSF severity_id values (FR-IN-06)."""

SEVERITY_NAMES = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

_ALIASES = {
    "unknown": 0,
    "info": 1,
    "informational": 1,
    "negligible": 1,
    "low": 2,
    "medium": 3,
    "moderate": 3,
    "high": 4,
    "important": 4,
    "critical": 5,
    "fatal": 6,
}


def severity_id_from_name(name: str | None) -> int:
    """Map a scanner severity word to an OCSF severity_id. Unknown words give 0."""
    if not name:
        return 0
    return _ALIASES.get(name.strip().lower(), 0)
