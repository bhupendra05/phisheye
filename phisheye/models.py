"""Data models for phisheye."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import List


class Verdict(str, Enum):
    SAFE = "LIKELY SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "LIKELY PHISHING"


_EMOJI = {
    Verdict.SAFE.value: "🟢",
    Verdict.SUSPICIOUS.value: "🟠",
    Verdict.PHISHING.value: "🔴",
}


@dataclass
class Signal:
    """A single risk indicator found in the URL."""

    id: str
    title: str
    severity: int  # contribution to the risk score
    detail: str


@dataclass
class Analysis:
    """The full risk assessment of a URL."""

    url: str
    host: str
    registrable_domain: str
    score: int
    verdict: Verdict
    signals: List[Signal] = field(default_factory=list)

    @property
    def emoji(self) -> str:
        return _EMOJI[self.verdict.value]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d
