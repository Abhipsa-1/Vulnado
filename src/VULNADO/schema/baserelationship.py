from neontology.baserelationship import BaseRelationship
from .basenode import CVE, MITRE, GSA
from typing import Optional


class CVEMapsToMITRE(BaseRelationship):
    __relationshiptype__ = "MAPS_TO"

    source: CVE
    target: MITRE
    score: Optional[float] = None


class CVEHasGSA(BaseRelationship):
    __relationshiptype__ = "HAS_GSA"

    source: CVE
    target: GSA
