"""OCSF helpers: severity map, class ids and fact extraction."""

from kavlotryx.ocsf.extract import FindingFacts, extract_facts
from kavlotryx.ocsf.severity import SEVERITY_NAMES, severity_id_from_name

CLASS_VULNERABILITY_FINDING = 2002
CLASS_COMPLIANCE_FINDING = 2003
CLASS_DETECTION_FINDING = 2004
FINDING_CLASSES = {
    CLASS_VULNERABILITY_FINDING,
    CLASS_COMPLIANCE_FINDING,
    CLASS_DETECTION_FINDING,
}

__all__ = [
    "CLASS_COMPLIANCE_FINDING",
    "CLASS_DETECTION_FINDING",
    "CLASS_VULNERABILITY_FINDING",
    "FINDING_CLASSES",
    "SEVERITY_NAMES",
    "FindingFacts",
    "extract_facts",
    "severity_id_from_name",
]
