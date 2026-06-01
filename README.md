<div align="center">

# phisheye 🎣👁️

### See the phish before you click.

**An offline, zero-dependency phishing-URL risk scanner that catches the tricks the human eye can't.**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)
[![Security](https://img.shields.io/badge/for-blue%20team-1f6feb.svg)](#)

</div>

---

```text
$ phisheye "http://paypal.com.secure-login.tk/account/verify"

🔴  LIKELY PHISHING  —  risk score 90/100
URL:    http://paypal.com.secure-login.tk/account/verify
Domain: secure-login.tk

Risk signals:
  • [50] Brand impersonation (paypal)
         'paypal' appears in the host but the real domain is 'secure-login.tk', not 'paypal.com'.
  • [20] Brand + credential keywords
         Combines a brand with action words (account, verify).
  • [15] High-abuse TLD .tk
         '.tk' is commonly used for free, disposable phishing domains.
  • [ 5] No HTTPS
         Real brands don't serve login pages over plain HTTP.
```

## Why phisheye?

Phishing is still the **#1 way breaches start**. The dangerous part of a malicious URL is
usually *invisible*: a Cyrillic letter that looks exactly like a Latin one, a brand name buried
three subdomains deep, a digit swapped for a letter. phisheye decodes the URL the way an
attacker built it and tells you — with reasons — how risky it is.

It runs **100% offline** (the URL never leaves your machine) and has **zero dependencies**, so
you can drop it into an air-gapped SOC or audit every line yourself.

## The attacks it catches

| Attack | Example | How phisheye catches it |
|--------|---------|-------------------------|
| 🎭 **Homograph / IDN** | `аpple.com` (Cyrillic а) | Decodes punycode, flags **mixed Unicode scripts** |
| 🔤 **Typosquatting** | `paypa1.com`, `g00gle.com` | **Levenshtein edit-distance** to known brands |
| 🪧 **Brand in subdomain** | `paypal.com.secure.tk` | Brand token present, real domain isn't theirs |
| 🕳️ **`@` host trick** | `apple.com@evil.ru` | Resolves the **real** host (after the `@`) |
| 🔢 **IP-literal host** | `http://192.168.0.5/login` | Raw IP instead of a domain |
| 🎲 **DGA domains** | `kq7v9zx1mwp2af.com` | **Shannon entropy** of the domain |
| 🔗 **URL shorteners** | `bit.ly/3xAbCdE` | Known-shortener list (hidden destination) |
| 🆓 **Disposable TLDs** | `.tk .ml .xyz .zip` | High-abuse TLD list |

Each signal carries a weight; the weights sum to a **0–100 risk score** →
🟢 `LIKELY SAFE` · 🟠 `SUSPICIOUS` · 🔴 `LIKELY PHISHING`.

## Install

```bash
pip install phisheye          # zero runtime dependencies
```

## Usage

```bash
# one URL — human readable
phisheye "https://paypa1.com/login"

# machine-readable (for SIEM / SOAR ingestion)
phisheye --json "https://xn--pple-43d.com"

# batch mode — score a whole list (SOC pipeline)
cat suspicious_urls.txt | phisheye --batch
```

**Exit codes** make it scriptable: `0` safe · `1` suspicious · `2` phishing — so you can gate
an email pipeline or block-list workflow on the result.

```python
from phisheye import analyze

report = analyze("http://paypal.com.secure-login.tk/verify")
print(report.verdict, report.score)        # Verdict.PHISHING 90
for signal in report.signals:
    print(signal.title, signal.detail)
```

## How it works

```
URL ─▶ parse (scheme/host/path)
    ─▶ decode IDN/punycode  ─▶ mixed-script (homograph) check
    ─▶ registrable domain   ─▶ brand impersonation + Levenshtein typosquat
    ─▶ heuristics           ─▶ IP host · @-trick · entropy(DGA) · TLD · shortener · keywords
    ─▶ weighted score       ─▶ 🟢 / 🟠 / 🔴 verdict + explained signals
```

Everything is transparent rules and classic algorithms (`phisheye/analyzer.py`,
`distance.py`, `homograph.py`) — no model, no API, no telemetry.

## ⚠️ Note

phisheye is a **heuristic risk signal**, not ground truth. It's tuned to flag the patterns
attackers actually use, but a high score isn't proof of malice and a low score isn't a
guarantee of safety. Use it as one input alongside reputation feeds and sandboxing.

## License

MIT
