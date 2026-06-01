"""The phishing-risk engine: run heuristics over a URL and produce a scored verdict."""
from __future__ import annotations

import math
import re
from typing import List, Set
from urllib.parse import urlsplit

from .brands import BRANDS, OFFICIAL
from .distance import levenshtein
from .homograph import decode_idna, has_punycode, is_mixed_script, scripts_in
from .models import Analysis, Signal, Verdict

# Free / disposable / high-abuse TLDs frequently used for phishing.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "work", "click",
    "country", "kim", "loan", "men", "cam", "rest", "quest", "sbs", "lol",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at",
}
KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "bank", "wallet", "unlock", "billing", "support", "webscr", "recover",
}
TWO_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "net.in", "org.in",
    "com.au", "net.au", "org.au", "co.jp", "com.br", "com.cn", "co.za",
    "com.sg", "co.nz", "com.mx", "co.kr",
}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_LEVEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _tokens(text: str) -> Set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def analyze(url: str) -> Analysis:
    """Analyze a URL and return a scored, explained phishing-risk Analysis."""
    raw = (url or "").strip()
    parsed = urlsplit(raw if "://" in raw else "http://" + raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    netloc = parsed.netloc
    path = parsed.path or ""

    uhost = decode_idna(host)
    reg = _registrable(uhost)
    reg_label = reg.split(".")[0] if reg else ""
    tld = reg.split(".")[-1] if "." in reg else ""
    host_tokens = _tokens(uhost)
    text_tokens = host_tokens | _tokens(path)

    signals: List[Signal] = []

    def add(sid: str, title: str, severity: int, detail: str) -> None:
        signals.append(Signal(sid, title, severity, detail))

    # ── host-shape attacks ────────────────────────────────────────────────────
    if _IPV4.match(host) or ":" in host:
        add("ip_host", "IP address used as host", 45,
            f"Host is a raw IP ({host}) instead of a domain — used to dodge domain reputation.")

    if parsed.username is not None or "@" in netloc:
        add("at_symbol", "'@' in URL hides the real host", 45,
            f"Browsers ignore everything before '@'; the true host is '{host}'.")

    # ── lookalike attacks ─────────────────────────────────────────────────────
    if has_punycode(host):
        add("punycode", "Punycode / IDN domain", 25,
            f"Uses internationalized (xn--) labels that decode to '{uhost}'.")

    if is_mixed_script(reg):
        add("homograph", "Mixed-script homograph", 50,
            f"'{reg}' mixes scripts ({', '.join(sorted(scripts_in(reg)))}) — "
            "lookalike letters from another alphabet.")

    # brand impersonation: a brand name appears in the host but it's not the real domain
    for brand in BRANDS:
        if brand in host_tokens and reg != OFFICIAL[brand]:
            add("brand_impersonation", f"Brand impersonation ({brand})", 50,
                f"'{brand}' appears in the host but the real domain is '{reg}', "
                f"not '{OFFICIAL[brand]}'.")
            break

    # typosquat: registered label is a near-miss of a brand
    if reg_label and reg not in OFFICIAL.values():
        for brand in BRANDS:
            threshold = 1 if len(brand) <= 5 else 2
            d = levenshtein(reg_label, brand)
            if 0 < d <= threshold and abs(len(reg_label) - len(brand)) <= 2:
                add("typosquat", f"Typosquat of {brand}", 55,
                    f"'{reg_label}' is {d} edit(s) from '{brand}' ({OFFICIAL[brand]}).")
                break

    # ── reputation / obfuscation ──────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"High-abuse TLD .{tld}", 15,
            f"'.{tld}' is commonly used for free, disposable phishing domains.")

    if reg in SHORTENERS or host in SHORTENERS:
        add("shortener", "URL shortener", 25,
            "Shorteners hide the real destination — expand before trusting it.")

    depth = max(0, len(uhost.split(".")) - 2)
    if depth > 3:
        add("many_subdomains", "Excessive subdomains", 15,
            f"{depth} subdomain levels — often used to bury a fake brand name.")

    entropy = _entropy(reg_label)
    if len(reg_label) >= 10 and entropy > 3.5:
        add("entropy", "Random-looking domain (possible DGA)", 25,
            f"Domain entropy {entropy:.2f} — looks algorithmically generated.")

    keywords = text_tokens & KEYWORDS
    is_official = reg in OFFICIAL.values()
    if keywords and any(b in host_tokens for b in BRANDS) and not is_official:
        add("credential_keywords", "Brand + credential keywords", 20,
            f"Combines a brand with action words ({', '.join(sorted(keywords))}).")
    elif keywords and (_IPV4.match(host) or tld in SUSPICIOUS_TLDS):
        add("credential_keywords", "Credential-harvest keywords on a risky host", 15,
            f"Action words ({', '.join(sorted(keywords))}) on a suspicious host.")

    if scheme != "https":
        add("non_https", "No HTTPS", 5,
            "Real brands don't serve login pages over plain HTTP.")

    if len(host) > 40:
        add("long_host", "Unusually long host", 10,
            f"Host is {len(host)} characters — used to push the real domain out of view.")

    if reg_label.count("-") >= 3:
        add("many_hyphens", "Many hyphens in domain", 10,
            "Lots of hyphens are common in lookalike domains.")

    # ── score + verdict ───────────────────────────────────────────────────────
    score = min(100, sum(s.severity for s in signals))
    if score >= 50:
        verdict = Verdict.PHISHING
    elif score >= 25:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE
    signals.sort(key=lambda s: -s.severity)

    return Analysis(url=raw, host=host, registrable_domain=reg, score=score,
                    verdict=verdict, signals=signals)
