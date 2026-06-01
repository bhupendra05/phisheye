"""phisheye — offline phishing-URL risk scanner."""
from __future__ import annotations

from .analyzer import analyze
from .models import Analysis, Signal, Verdict

__version__ = "0.1.0"
__all__ = ["analyze", "Analysis", "Signal", "Verdict"]
