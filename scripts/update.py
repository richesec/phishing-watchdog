import requests
import json
import os
import time
import dns.resolver
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

try:
    from Levenshtein import distance as levenshtein_distance
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False

# =============================================================================
# CONFIGURATION
# =============================================================================

# Suspicious keywords - domains containing these are flagged
KEYWORDS = [
    # Authentication
    "login", "signin", "sign-in", "logon", "log-on", "authenticate",
    "verification", "verify", "confirm", "validate",
    
    # Security
    "secure", "security", "protected", "safety", "safe",
    "ssl", "https", "encryption",
    
    # Financial
    "bank", "banking", "payment", "wallet", "crypto", "bitcoin", "ethereum",
    "finance", "transfer", "wire", "invoice", "billing", "account",
    
    # Support/Service
    "support", "helpdesk", "service", "customer", "help", "assistance",
    "recovery", "restore", "unlock", "suspended", "disabled",
    
    # Urgency triggers
    "urgent", "alert", "warning", "notice", "update", "action", "required",
    "immediately", "expire", "expired", "limited",
    
    # Credentials
    "password", "passwd", "credential", "reset", "recover",
    "otp", "token", "2fa", "mfa",
    
    # Common phishing terms
    "webmail", "mailbox", "outlook", "office365", "microsoft365",
    "icloud", "appleid", "google-", "facebook-", "instagram-",
]

# Major brands to check for similarity (typosquatting detection)
BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "facebook",
    "instagram", "twitter", "netflix", "spotify", "dropbox", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usbank",
    "coinbase", "binance", "kraken", "metamask", "opensea",
    "outlook", "office365", "onedrive", "sharepoint", "teams",
    "icloud", "appstore", "itunes", "imessage",
    "whatsapp", "telegram", "signal", "discord", "slack",
    "adobe", "zoom", "webex", "docusign", "salesforce",
    "fedex", "ups", "usps", "dhl",
    "att", "verizon", "tmobile", "comcast", "xfinity",
]

# Similarity threshold (0-1, lower = more strict)
BRAND_SIMILARITY_THRESHOLD = 0.8

OUTPUT_JSON = "data/domains.json"
FEED_JSON = "data/feed.json"
SITE_URL = "https://richesec.github.io/phishing-watchdog"
CHECK_DIR = "check"

# =============================================================================
# FUNCTIONS
# =============================================================================

def get_recent_domains():
    """Fetch domains from crt.sh CT log by querying specific keywords."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(hours=6)
    
    # Query terms - subset of keywords that are most indicative of phishing
    QUERY_TERMS = [
        "login", "signin", "secure", "verify", "account",
        "paypal", "amazon", "apple", "google", "microsoft",
        "bank", "wallet", "crypto", "support", "password"
    ]
    
    all_domains = set()
    
    for term in QUERY_TERMS:
        print(f"[*] Querying crt.sh for '%{term}%'...")
        
        try:
            # Query crt.sh for domains containing the term
            url = f"https://crt.sh/?q=%25{term}%25&output=json"
            r = requests.get(url, timeout=30, headers={
                'User-Agent': 'PhishingWatchdog/1.0'
            })
            
            if r.status_code != 200:
                print(f"    [!] Status {r.status_code}, skipping")
                continue
                
            try:
                results = r.json()
            except:
                print(f"    [!] Invalid JSON response, skipping")
                continue
            
            # Filter by date
            count = 0
            for c in results:
                # Check if cert was issued recently
                not_before = c.get("not_before", "")
                if not_before:
                    try:
                        cert_date = datetime.fromisoformat(not_before.replace("T", " ").split(".")[0])
                        if cert_date.replace(tzinfo=timezone.utc) < past:
                            continue
                    except:
                        pass
                
                name = c.get("common_name") or ""
                if name and "." in name:
                    all_domains.add(name.lower().strip())
                    count += 1

                san = c.get("name_value") or ""
                for d in san.split("\n"):
                    d = d.strip().lower()
                    if "." in d and not d.startswith("*"):
                        all_domains.add(d)
                        count += 1
            
            print(f"    [+] Found {count} recent domains")
            
            # Brief pause to avoid rate limiting
            time.sleep(1)
            
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout, skipping")
        except Exception as e:
            print(f"    [!] Error: {e}")

    print(f"[+] Total unique domains: {len(all_domains)}")
    return list(all_domains)


def get_domain_base(domain):
    """Extract base domain name without TLD for comparison."""
    parts = domain.split(".")
    if len(parts) >= 2:
        # Get the main part (before TLD)
        return parts[-2]
    return domain


def calculate_brand_similarity(domain):
    """Check if domain is similar to any known brand (typosquatting detection)."""
    if not HAS_LEVENSHTEIN:
        return None, 0
    
    domain_base = get_domain_base(domain)
    
    best_match = None
    best_score = 0
    
    for brand in BRANDS:
        # Check if brand is substring
        if brand in domain_base:
            return brand, 1.0
        
        # Calculate similarity using Levenshtein distance
        max_len = max(len(domain_base), len(brand))
        if max_len == 0:
            continue
            
        dist = levenshtein_distance(domain_base, brand)
        similarity = 1 - (dist / max_len)
        
        if similarity > best_score:
            best_score = similarity
            best_match = brand
    
    return best_match, best_score


def is_suspicious(domain):
    """Check if domain matches keywords or looks like a brand typo."""
    # Check for keyword matches
    matched_keywords = []
    for k in KEYWORDS:
        if k in domain:
            matched_keywords.append(k)
    
    # Check for brand similarity
    brand_match, similarity = calculate_brand_similarity(domain)
    brand_alert = brand_match and similarity >= BRAND_SIMILARITY_THRESHOLD
    
    if matched_keywords or brand_alert:
        return {
            "suspicious": True,
            "keywords": matched_keywords,
            "brand_match": brand_match if brand_alert else None,
            "brand_similarity": round(similarity, 2) if brand_alert else None
        }
    
    return {"suspicious": False}


def has_mx(domain):
    """Check if domain has MX records (can receive email)."""
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except:
        return False


def calculate_threat_score(entry):
    """
    Calculate a threat score (0-100) for a domain.
    
    Scoring breakdown:
    - MX Record present: +25 points (can receive phishing emails)
    - Brand similarity: up to +35 points (based on similarity %)
    - Keywords: +5 points each (max +25 points)
    - High-risk keywords: +15 bonus (login, password, bank, crypto)
    """
    score = 0
    
    # MX Record - Can receive emails (major red flag)
    if entry.get("mx"):
        score += 25
    
    # Brand similarity scoring
    similarity = entry.get("brand_similarity", 0) or 0
    if similarity > 0:
        # Scale: 80% match = 28 points, 100% match = 35 points
        score += int(similarity * 35)
    
    # Keyword scoring
    keywords = entry.get("keywords", [])
    keyword_score = min(len(keywords) * 5, 25)  # Cap at 25
    score += keyword_score
    
    # High-risk keyword bonus
    high_risk = ["login", "password", "passwd", "bank", "crypto", "wallet", "verify", "secure"]
    if any(k in high_risk for k in keywords):
        score += 15
    
    # Cap at 100
    return min(score, 100)


def get_threat_level(score):
    """Convert numeric score to threat level label."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def has_a_record(domain):
    """Check if domain resolves to an IP."""
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except:
        return False


def load_existing():
    """Load existing domain data."""
    if not os.path.exists(OUTPUT_JSON):
        return []
    with open(OUTPUT_JSON, "r") as f:
        return json.load(f)


def save_json(data):
    """Save domain data to JSON."""
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(data, f, indent=2)


def save_feed(data):
    """Generate JSON feed with latest domains."""
    items = []
    for d in reversed(data[-50:]):
        url = f"{SITE_URL}/check/{quote(d['domain'])}.html"
        threat_score = d.get("threat_score", calculate_threat_score(d))
        items.append({
            "domain": d["domain"],
            "link": url,
            "date": d["date"],
            "mx": d.get("mx", False),
            "keywords": d.get("keywords", []),
            "brand_match": d.get("brand_match"),
            "brand_similarity": d.get("brand_similarity"),
            "threat_score": threat_score,
            "threat_level": get_threat_level(threat_score)
        })
    
    os.makedirs(os.path.dirname(FEED_JSON), exist_ok=True)
    with open(FEED_JSON, "w") as f:
        json.dump(items, f, indent=2)


def generate_page(d):
    """Generate warning page for a suspicious domain."""
    os.makedirs(CHECK_DIR, exist_ok=True)
    
    # Sanitize filename
    safe_name = d['domain'].replace('/', '_').replace('\\', '_')
    path = f"{CHECK_DIR}/{safe_name}.html"
    
    # Calculate threat score if not present
    threat_score = d.get("threat_score", calculate_threat_score(d))
    threat_level = d.get("threat_level", get_threat_level(threat_score))
    
    # Threat level colors
    threat_colors = {
        "CRITICAL": ("#ff1744", "#ff1744"),
        "HIGH": ("#ff4757", "#ff6b7a"),
        "MEDIUM": ("#ffa502", "#ffb733"),
        "LOW": ("#00ff88", "#33ff9f")
    }
    threat_color = threat_colors.get(threat_level, ("#ffa502", "#ffb733"))
    
    keywords_html = ""
    if d.get("keywords"):
        keywords_html = f"""<p><strong>Matched Keywords:</strong> {', '.join(d['keywords'])}</p>"""
    
    brand_html = ""
    if d.get("brand_match"):
        similarity = d.get('brand_similarity', 0) or 0
        brand_html = f"""
<p><strong>⚠️ Brand Impersonation:</strong> Targeting <code>{d['brand_match']}</code></p>
<p><strong>Similarity Score:</strong> <span style="color: {threat_color[0]}; font-weight: bold;">{similarity * 100:.0f}%</span> match (Levenshtein distance)</p>
"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<title>⚠️ {d['domain']} - Threat Score {threat_score}/100</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
    --bg-primary: #0a0a0f;
    --bg-card: #1a1a24;
    --border: #2a2a3a;
    --text-primary: #fff;
    --text-secondary: #8b8b9e;
    --accent: #00ff88;
    --danger: #ff4757;
    --threat-color: {threat_color[0]};
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    padding: 2rem;
    line-height: 1.6;
}}
.container {{ max-width: 800px; margin: 0 auto; }}
.threat-header {{
    text-align: center;
    padding: 2rem;
    background: linear-gradient(135deg, {threat_color[0]}22, {threat_color[1]}11);
    border: 1px solid {threat_color[0]}44;
    border-radius: 16px;
    margin-bottom: 2rem;
}}
.threat-badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    background: {threat_color[0]};
    color: #000;
    padding: 0.5rem 1rem;
    border-radius: 50px;
    font-weight: 700;
    font-size: 0.9rem;
    margin-bottom: 1rem;
}}
.threat-score {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 4rem;
    font-weight: 700;
    color: {threat_color[0]};
    line-height: 1;
}}
.threat-score span {{
    font-size: 1.5rem;
    color: var(--text-secondary);
}}
.domain-name {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.25rem;
    color: var(--danger);
    word-break: break-all;
    margin-top: 1rem;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
}}
.card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}}
.card h2 {{
    font-size: 1.1rem;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}
.card p {{ margin-bottom: 0.5rem; color: var(--text-secondary); }}
.card strong {{ color: var(--text-primary); }}
.card code {{
    background: var(--bg-primary);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
}}
.card ul {{ margin-left: 1.5rem; color: var(--text-secondary); }}
.card li {{ margin-bottom: 0.25rem; }}
.score-breakdown {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}}
.score-item {{
    background: var(--bg-primary);
    padding: 1rem;
    border-radius: 8px;
    text-align: center;
}}
.score-item .value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
}}
.score-item .label {{
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
}}
.back-link {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--accent);
    text-decoration: none;
    font-weight: 500;
    margin-top: 1rem;
}}
.back-link:hover {{ text-decoration: underline; }}
.mx-warning {{
    color: var(--danger);
    font-weight: 600;
}}
</style>
</head>
<body>
<div class="container">

<div class="threat-header">
    <div class="threat-badge">⚡ {threat_level} THREAT</div>
    <div class="threat-score">{threat_score}<span>/100</span></div>
    <div class="domain-name">🔗 {d['domain']}</div>
</div>

<div class="card">
    <h2>📊 Threat Analysis</h2>
    <div class="score-breakdown">
        <div class="score-item">
            <div class="value" style="color: {'var(--danger)' if d.get('mx') else 'var(--accent)'}">{'YES' if d.get('mx') else 'NO'}</div>
            <div class="label">MX Record</div>
        </div>
        <div class="score-item">
            <div class="value" style="color: var(--threat-color)">{d.get('brand_similarity', 0) * 100 if d.get('brand_similarity') else 0:.0f}%</div>
            <div class="label">Brand Match</div>
        </div>
        <div class="score-item">
            <div class="value">{len(d.get('keywords', []))}</div>
            <div class="label">Keywords</div>
        </div>
        <div class="score-item">
            <div class="value">{'YES' if d.get('has_ip') else '?'}</div>
            <div class="label">Resolves</div>
        </div>
    </div>
</div>

<div class="card">
    <h2>🔍 Detection Details</h2>
    <p><strong>Detected:</strong> {d['date']}</p>
    <p><strong>MX Record:</strong> {'<span class="mx-warning">Yes ⚠️ Can receive phishing emails</span>' if d.get('mx') else 'No'}</p>
    {keywords_html}
    {brand_html}
</div>

<div class="card">
    <h2>ℹ️ What This Means</h2>
    <p>This domain was detected in Certificate Transparency logs and matches patterns commonly used in phishing attacks.</p>
    <p>The <strong>Threat Score</strong> is calculated based on:</p>
    <ul>
        <li>MX Records (+25 pts) - Can receive emails</li>
        <li>Brand Similarity (up to +35 pts) - Typosquatting detection</li>
        <li>Keyword Matches (+5 pts each, max +25)</li>
        <li>High-Risk Keywords (+15 pts bonus)</li>
    </ul>
</div>

<div class="card">
    <h2>🛡️ Protect Yourself</h2>
    <ul>
        <li>Never enter credentials on unfamiliar websites</li>
        <li>Check URLs carefully for typos</li>
        <li>Enable two-factor authentication</li>
        <li>Use a password manager</li>
        <li>Report suspicious domains to your security team</li>
    </ul>
</div>

<a href="../index.html" class="back-link">← Back to Dashboard</a>

</div>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def main(test_mode=False):
    print("=" * 60)
    print("🐕 Phishing Domain Watchdog - Starting Update")
    if test_mode:
        print("   [TEST MODE - Using sample data]")
    print("=" * 60)
    
    if test_mode:
        # Sample domains for testing
        new_domains = [
            "secure-paypal-login.com",
            "amazon-account-verify.net",
            "googl3.com",  # typosquatting
            "microsft-support.com",  # typosquatting
            "bank-secure-login.org",
            "crypto-wallet-recovery.io",
            "netflix-password-reset.com",
            "faceb00k-verify.com",  # typosquatting
            "apple-id-confirm.net",
            "coinbase-support-help.com",
            "legitimate-website.com",  # should NOT be flagged
            "random-domain.org",  # should NOT be flagged
        ]
    else:
        new_domains = get_recent_domains()
    
    existing = load_existing()
    existing_domains = {e["domain"] for e in existing}
    
    added_count = 0
    
    for d in new_domains:
        # Skip already processed domains
        if d in existing_domains:
            continue
        
        result = is_suspicious(d)
        if not result["suspicious"]:
            print(f"[.] Clean: {d}")
            continue

        print(f"[!] Suspicious: {d}")
        if result.get("keywords"):
            print(f"    Keywords: {', '.join(result['keywords'])}")
        if result.get("brand_match"):
            print(f"    Brand Match: {result['brand_match']} ({result['brand_similarity']*100:.0f}%)")

        entry = {
            "domain": d,
            "mx": has_mx(d) if not test_mode else False,
            "has_ip": has_a_record(d) if not test_mode else True,
            "keywords": result.get("keywords", []),
            "brand_match": result.get("brand_match"),
            "brand_similarity": result.get("brand_similarity"),
            "date": datetime.now(timezone.utc).isoformat()
        }
        
        # Calculate threat score
        entry["threat_score"] = calculate_threat_score(entry)
        entry["threat_level"] = get_threat_level(entry["threat_score"])
        print(f"    Threat Score: {entry['threat_score']}/100 ({entry['threat_level']})")

        existing.append(entry)
        generate_page(entry)
        added_count += 1

    # Keep latest 1000
    existing = existing[-1000:]

    save_json(existing)
    save_feed(existing)
    
    print("=" * 60)
    print(f"✅ Complete! Added {added_count} new suspicious domains")
    print(f"📁 Total domains tracked: {len(existing)}")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Phishing Domain Watchdog")
    parser.add_argument("--test", action="store_true", help="Run in test mode with sample data")
    args = parser.parse_args()
    main(test_mode=args.test)

