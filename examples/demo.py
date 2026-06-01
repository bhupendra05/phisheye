"""Run phisheye over a spread of real phishing tricks."""
from phisheye import analyze

EXAMPLES = [
    "https://www.google.com/search?q=hello",          # legit
    "https://www.paypal.com/signin",                  # legit brand
    "http://paypal.com.secure-login.tk/account/verify",  # brand in subdomain
    "https://paypa1.com/login",                       # typosquat (digit 1 for l)
    "https://аpple.com/login",                   # homograph (Cyrillic а)
    "http://192.168.44.7/wp-login/verify",            # IP host
    "http://www.apple.com@evil.ru/login",             # @-trick
    "https://bit.ly/3xAbCdE",                         # shortener
    "https://kq7v9zx1mwp2af.com/login",               # DGA-looking
    "http://secure-update-account-confirm-now.xyz/billing",  # keyword soup
]


def main():
    print("phisheye 🎣👁️  — phishing-URL risk scan\n")
    print(f"{'VERDICT':<18} {'SCORE':>6}   URL")
    print("-" * 80)
    for url in EXAMPLES:
        a = analyze(url)
        print(f"{a.emoji} {a.verdict.value:<16} {a.score:>4}/100   {url}")

    # one detailed report
    print("\n" + "=" * 80)
    a = analyze("http://paypal.com.secure-login.tk/account/verify")
    print(f"Detailed report — {a.url}\n")
    print(f"{a.emoji} {a.verdict.value} (score {a.score}/100), real domain: {a.registrable_domain}\n")
    for s in a.signals:
        print(f"  • [{s.severity:>2}] {s.title}\n        {s.detail}")


if __name__ == "__main__":
    main()
