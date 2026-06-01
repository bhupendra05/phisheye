"""Unicode / IDN homograph detection.

Homograph attacks register domains with letters that look identical to Latin ones but come
from a different script — e.g. Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061). They reach the
wire as punycode (``xn--``). We decode them and flag domains that mix scripts.
"""
from __future__ import annotations

import unicodedata
from typing import Optional, Set


def decode_idna(host: str) -> str:
    """Decode any ``xn--`` (punycode) labels back to their Unicode form."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label[4:].encode("ascii").decode("punycode"))
            except Exception:
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


def has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def _script_of(ch: str) -> Optional[str]:
    """Coarse script name of a character via its Unicode name (LATIN / CYRILLIC / GREEK…)."""
    try:
        return unicodedata.name(ch).split(" ")[0]
    except ValueError:
        return None


def scripts_in(text: str) -> Set[str]:
    scripts = set()
    for ch in text:
        if ch.isalpha():
            script = _script_of(ch)
            if script:
                scripts.add(script)
    return scripts


def is_mixed_script(text: str) -> bool:
    """True if the text's letters come from more than one script — the homograph signature."""
    return len(scripts_in(text)) > 1
