"""
Remediator Factory & Vendor Registry.
Dispatches to the appropriate vendor remediation engine based on device family.
"""

from typing import Dict, Type
from backend.app.remediation.base import BaseRemediator
from backend.app.remediation.cisco import CiscoRemediator
from backend.app.remediation.fortinet import FortinetRemediator
from backend.app.remediation.palo_alto import PaloAltoRemediator

_REMEDIATOR_REGISTRY: Dict[str, BaseRemediator] = {
    "cisco": CiscoRemediator(),
    "fortinet": FortinetRemediator(),
    "palo alto": PaloAltoRemediator(),
    "paloalto": PaloAltoRemediator(),
}


def get_remediator(vendor: str) -> BaseRemediator:
    """
    Retrieves the vendor-specific remediator instance.
    Raises ValueError if vendor is unknown or unsupported.
    """
    key = vendor.lower().strip()
    if "cisco" in key:
        return _REMEDIATOR_REGISTRY["cisco"]
    elif "fortinet" in key or "fortigate" in key or "fortios" in key:
        return _REMEDIATOR_REGISTRY["fortinet"]
    elif "palo" in key or "pan" in key:
        return _REMEDIATOR_REGISTRY["palo alto"]
    else:
        raise ValueError(
            f"Unsupported vendor '{vendor}' for automated remediation. "
            f"Supported vendors are: Cisco, Fortinet, Palo Alto."
        )


def list_supported_vendors() -> list[str]:
    """Returns the list of supported vendor canonical names."""
    return ["Cisco", "Fortinet", "Palo Alto"]
