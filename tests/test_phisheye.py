"""Tests for phisheye — one per attack class plus the scoring/verdict logic."""
import json

from phisheye import analyze, Verdict
from phisheye.distance import levenshtein
from phisheye.homograph import decode_idna, is_mixed_script
from phisheye.analyzer import _registrable, _entropy


def ids(a):
    return {s.id for s in a.signals}


# ── clean URLs ────────────────────────────────────────────────────────────────
def test_legit_url_is_safe():
    a = analyze("https://www.google.com/search?q=hello")
    assert a.verdict is Verdict.SAFE
    assert a.score == 0
    assert a.signals == []


def test_legit_brand_not_flagged():
    a = analyze("https://www.paypal.com/signin")
    assert a.verdict is Verdict.SAFE
    assert "brand_impersonation" not in ids(a)


# ── brand attacks ─────────────────────────────────────────────────────────────
def test_brand_impersonation_subdomain():
    a = analyze("http://paypal.com.secure-login.tk/account/verify")
    assert a.verdict is Verdict.PHISHING
    assert "brand_impersonation" in ids(a)
    assert "suspicious_tld" in ids(a)


def test_typosquat():
    a = analyze("https://paypa1.com/login")   # paypa1 vs paypal
    assert "typosquat" in ids(a)
    assert a.verdict is Verdict.PHISHING


# ── host-shape attacks ────────────────────────────────────────────────────────
def test_ip_host():
    a = analyze("http://192.168.0.5/login")
    assert "ip_host" in ids(a)


def test_at_symbol_trick_resolves_real_host():
    a = analyze("http://www.apple.com@evil.ru/login")
    assert "at_symbol" in ids(a)
    assert a.host == "evil.ru"          # the REAL host, not apple.com
    assert a.verdict is Verdict.PHISHING


# ── unicode homograph ─────────────────────────────────────────────────────────
def test_homograph_mixed_script():
    a = analyze("https://аpple.com/login")   # Cyrillic 'а' + Latin 'pple'
    assert "homograph" in ids(a)
    assert a.verdict is Verdict.PHISHING


def test_punycode_decodes():
    # 'xn--pple-43d' decodes to 'аpple' (Cyrillic а)
    assert decode_idna("xn--pple-43d.com").startswith("аpple")
    a = analyze("https://xn--pple-43d.com")
    assert "homograph" in ids(a) or "punycode" in ids(a)


# ── obfuscation / reputation ──────────────────────────────────────────────────
def test_url_shortener():
    a = analyze("https://bit.ly/3xAbCdE")
    assert "shortener" in ids(a)
    assert a.verdict is Verdict.SUSPICIOUS


def test_dga_high_entropy():
    a = analyze("https://kq7v9zx1mwp2af.com/login")
    assert "entropy" in ids(a)


# ── unit pieces ───────────────────────────────────────────────────────────────
def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("google", "g00gle") == 2
    assert levenshtein("abc", "abc") == 0


def test_registrable_handles_two_level_tld():
    assert _registrable("www.example.co.uk") == "example.co.uk"
    assert _registrable("a.b.c.example.com") == "example.com"


def test_mixed_script_detection():
    assert is_mixed_script("аpple")     # Cyrillic + Latin
    assert not is_mixed_script("apple")      # pure Latin


def test_entropy_random_higher_than_word():
    assert _entropy("kq7v9zx1mwp2af") > _entropy("paypal")


# ── output contract ───────────────────────────────────────────────────────────
def test_to_dict_is_json_serializable():
    a = analyze("http://paypal.com.secure-login.tk/verify")
    blob = json.dumps(a.to_dict())          # must not raise
    parsed = json.loads(blob)
    assert parsed["verdict"] == "LIKELY PHISHING"
    assert isinstance(parsed["signals"], list)
