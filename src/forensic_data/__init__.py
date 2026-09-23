"""Public package metadata for forensic-data."""

from importlib.metadata import version
from typing import Final

__all__: Final[tuple[str, ...]] = ("__version__",)

__version__: Final[str] = version("forensic-data")
