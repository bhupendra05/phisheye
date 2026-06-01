"""Levenshtein (edit) distance — the core of typosquat detection."""
from __future__ import annotations


def levenshtein(a: str, b: str) -> int:
    """Minimum single-character edits (insert/delete/substitute) to turn ``a`` into ``b``.

    Classic dynamic-programming solution using two rows: O(len(a)·len(b)) time, O(len(b))
    space.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current.append(min(
                previous[j] + 1,       # deletion
                current[j - 1] + 1,    # insertion
                previous[j - 1] + cost,  # substitution
            ))
        previous = current
    return previous[-1]
