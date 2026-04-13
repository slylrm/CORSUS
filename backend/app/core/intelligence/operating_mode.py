from enum import Enum


class OperatingMode(str, Enum):
    SAFE_READ_ONLY = "SAFE_READ_ONLY"

__all__ = ["OperatingMode"]
