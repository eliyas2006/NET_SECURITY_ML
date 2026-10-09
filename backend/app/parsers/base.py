"""
Base Parser Interface and Detection Result Models.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel
from backend.app.schemas.normalized import NormalizedConfiguration


class VendorIdentificationResult(BaseModel):
    vendor: str
    confidence: float  # 0.0 to 1.0
    confidence_level: str  # High, Medium, Low
    reason: str
    detected_syntax: Optional[str] = None
    suggested_device_type: str = "Firewall/Router"


class BaseParser(ABC):
    """Abstract Base Class for vendor-specific configuration parsers."""

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Name of the vendor handled by this parser."""
        pass

    @abstractmethod
    def parse(self, content: str) -> NormalizedConfiguration:
        """
        Parses raw configuration text and returns a vendor-neutral NormalizedConfiguration object.
        """
        pass
