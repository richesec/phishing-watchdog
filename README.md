# Phishing Domain Watchdog 🐕

A lightweight tool that monitors Certificate Transparency logs for suspicious domains matching phishing-related keywords and brand typosquatting patterns.

## Features

✅ **70+ Phishing Keywords** - Detects authentication, security, financial, and urgency-related terms  
✅ **Brand Similarity Detection** - Uses Levenshtein distance to catch typosquatting (e.g., `googl3.com` → `google`)  
✅ **45+ Brand Watchlist** - Monitors for impersonation of major brands (PayPal, Amazon, Microsoft, etc.)  
✅ **MX Record Checking** - Flags domains capable of receiving phishing emails  
✅ **Static Site Generation** - Creates styled warning pages for each suspicious domain  
✅ **JSON Feed** - Consumable feed for security tools and dashboards

## How It Works

1. **Every 6 hours**, GitHub Actions triggers the update script
2. **Queries crt.sh** for certificates containing suspicious keywords
3. **Filters domains** using keyword matching AND brand similarity detection
4. **Enriches data** by checking for MX records and IP resolution
5. **Generates static pages** for each suspicious domain
6. **Updates the feed** with the latest detections
7. **Commits changes** automatically

## Schedule

The workflow runs at:

- 00:00 UTC → covers past 6 hours
- 06:00 UTC → covers past 6 hours
- 12:00 UTC → covers past 6 hours
- 18:00 UTC → covers past 6 hours

**Perfect coverage with zero gaps.**

## Detection Methods

### Keyword Matching

Domains containing these categories are flagged:

- **Authentication**: login, signin, verify, confirm, authenticate
- **Security**: secure, protected, ssl, encryption
- **Financial**: bank, payment, wallet, crypto, bitcoin
- **Support**: support, helpdesk, recovery, unlock
- **Urgency**: urgent, alert, warning, expire, limited
- **Credentials**: password, reset, token, 2fa, mfa

### Brand Typosquatting

Uses Levenshtein distance to detect domains similar to major brands:

- PayPal, Amazon, Apple, Google, Microsoft, Facebook
- Netflix, Spotify, Dropbox, LinkedIn, Twitter
- Chase, Wells Fargo, Bank of America, Coinbase, Binance
- And 30+ more brands...

**Example detections:**

- `googl3.com` → 83% similar to `google`
- `amaz0n-login.com` → Contains `amazon` brand
- `paypa1-secure.net` → Typosquatting attempt

## Project Structure

```
phishing-watchdog/
├─ data/
│  ├─ domains.json      # All detected domains (max 1000)
│  └─ feed.json         # Latest 50 domains for feed
├─ check/
│  └─ (auto-generated)  # Individual domain warning pages
├─ scripts/
│  └─ update.py         # Main update script
├─ .github/
│  └─ workflows/
│     └─ update.yml     # GitHub Actions workflow
├─ index.html           # Landing page
└─ README.md
```

## Setup

1. **Fork this repository**
2. **Enable GitHub Pages** (Settings → Pages → Deploy from main branch)
3. **Update `SITE_URL`** in `scripts/update.py` with your GitHub Pages URL
4. **Enable Actions** if not already enabled

## Local Testing

```bash
# Install dependencies
pip install requests dnspython python-Levenshtein

# Run in test mode (uses sample data, no API calls)
python scripts/update.py --test

# Run normally (queries crt.sh)
python scripts/update.py
```

## Configuration

Edit `scripts/update.py` to customize:

```python
# Add/remove keywords
KEYWORDS = ["login", "secure", ...]

# Add/remove monitored brands
BRANDS = ["paypal", "amazon", ...]

# Adjust similarity threshold (0.8 = 80% match required)
BRAND_SIMILARITY_THRESHOLD = 0.8
```

## Data Source

All data comes from [crt.sh](https://crt.sh), which queries Certificate Transparency logs - the same data source used by security researchers worldwide.

## Sample Output

```
🐕 Phishing Domain Watchdog - Starting Update
============================================================
[!] Suspicious: secure-paypal-login.com
    Keywords: login, secure
    Brand Match: paypal (100%)
[!] Suspicious: googl3.com
    Brand Match: google (83%)
[!] Suspicious: bank-secure-login.org
    Keywords: login, secure, bank
[.] Clean: legitimate-website.com
============================================================
✅ Complete! Added 10 new suspicious domains
```

## License

MIT
