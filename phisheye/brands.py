"""Commonly impersonated brands and their official registrable domains.

The dict key is the brand token; the value is the legitimate domain. The token is also
the first label of the legit domain, which keeps brand-impersonation and typosquat checks
consistent.
"""
from __future__ import annotations

OFFICIAL = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "github": "github.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "outlook": "outlook.com",
    "icloud": "icloud.com",
    "yahoo": "yahoo.com",
    "spotify": "spotify.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "hsbc": "hsbc.com",
    "hdfcbank": "hdfcbank.com",
    "icicibank": "icicibank.com",
    "paytm": "paytm.com",
}

BRANDS = set(OFFICIAL.keys())
