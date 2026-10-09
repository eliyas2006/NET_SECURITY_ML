"""
Parsers module entrypoint and factory.
"""

from typing import Optional
from backend.app.parsers.base import BaseParser, VendorIdentificationResult
from backend.app.parsers.cisco import CiscoParser
from backend.app.parsers.fortinet import FortinetParser
from backend.app.parsers.palo_alto import PaloAltoParser
from backend.app.parsers.detector import detect_vendor


def get_parser(vendor: str) -> BaseParser:
    v = vendor.lower()
    if "cisco" in v:
        return CiscoParser()
    elif "fortinet" in v or "fortigate" in v:
        return FortinetParser()
    elif "palo" in v or "pan" in v:
        return PaloAltoParser()
    else:
        raise ValueError(f"Unsupported vendor parser: '{vendor}'. Supported vendors: Cisco, Fortinet, Palo Alto.")


__all__ = [
    "BaseParser",
    "VendorIdentificationResult",
    "CiscoParser",
    "FortinetParser",
    "PaloAltoParser",
    "detect_vendor",
    "get_parser",
]
