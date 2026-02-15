from neontology.basenode import BaseNode
from typing import Optional


class CVE(BaseNode):
    __primarylabel__ = "CVE"
    __primaryproperty__ = ["cve_id","description"]
    __secondaryproperties__ = [ "severity","description","references","affected_software"]
    __tertiaryproperties__ = ["affected_software", "references"]

    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    affected_software: Optional[list] = None
    references: Optional[list] = None


class MITRE(BaseNode):
    __primarylabel__ = "MITRE"
    __primaryproperty__ = "technique_description"
    __secondaryproperties__ = ["technique_id", "technique_name", "tactic"]
    __tertiaryproperties__ = ["platforms"]

    technique_id: str
    technique_name: Optional[str] = None
    technique_description: Optional[str] = None
    tactic: Optional[str] = None



class GSA(BaseNode):
    __primarylabel__ = "GSA"
    __primaryproperty__ = ["ghsa_id","cve_id"]
    __secondaryproperties__ = ["package_name", "severity", "vulnerable_versions", "fixed_version"]
    __tertiaryproperties__ = ["references"]

    gsa_id: str
    package_name: Optional[str] = None
    severity: Optional[str] = None


print("Schema basenode.py loaded.")