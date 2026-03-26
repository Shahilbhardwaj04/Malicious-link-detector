# Phishing Link Detector

Advanced URL phishing detection using heuristics, VirusTotal API, SSL inspection, domain reputation checks, and threat database integration.

## Setup

1. Create and activate a Python virtualenv:

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create `.env` file with your API keys:

```env
VIRUSTOTAL_API_KEY=your_key_here
FLASK_ENV=development
FLASK_APP=app.py

# Optional:
PHISHTANK_API_KEY=your_key_here
```

4. Run the application:

```bash
flask run --port=5001
```

Open http://127.0.0.1:5001 in your browser.

## Features

### URL Heuristics
Analyzes URL patterns for suspicious indicators:
- IP addresses in domain
- @ symbol usage (credential injection)
- Excessive subdomains
- Long URLs
- Punycode usage
- Double slashes in path

### VirusTotal Integration
Queries VirusTotal v3 API for malware/phishing detection:
- Requires `VIRUSTOTAL_API_KEY` (free tier available)
- Returns detection counts (malicious, suspicious, harmless)
- Cached for 6 hours

### SSL Certificate Inspection
Validates SSL certificates:
- Subject and issuer verification
- Expiry date checking
- Certificate chain validation
- Cached for 12 hours

### Domain Reputation
IP resolution and WHOIS lookup:
- IP address resolution
- WHOIS registration info
- RDAP fallback for WHOIS failures
- Cached for 24 hours

### URLhaus Database
Checks abuse.ch URLhaus for known malicious URLs:
- No authentication required
- Free, unauthenticated API access
- Malware/phishing URL detection
- Cached for 1 hour

### PhishTank Integration
Checks PhishTank phishing database (optional):
- Free API available (registration required)
- Set `PHISHTANK_API_KEY` in `.env` for access
- Cached for 1 hour

### Risk Scoring
Weighted scoring system combining all checks:
- Verdict: Malicious, Suspicious, or Likely harmless
- Risk breakdown showing contributing factors
- Points system for each risk signal

## API Endpoint

**POST** `/api/check`

Request body:
```json
{"url": "https://example.com"}
```

Response:
```json
{
  "url": "https://example.com",
  "heuristics": {
    "uses_https": true,
    "has_at_symbol": false,
    "long_url": false,
    "ip_in_domain": false,
    "suspicious_chars": false,
    "has_double_slash_in_path": false,
    "host_length": 11,
    "num_subdomains": 1,
    "uses_punycode": false
  },
  "virustotal": {
    "stats": {
      "malicious": 0,
      "suspicious": 0,
      "harmless": 80,
      "undetected": 10
    }
  },
  "ssl": {
    "subject": {"commonName": "example.com"},
    "issuer": {"commonName": "Let's Encrypt", "organizationName": "Let's Encrypt", "countryName": "US"},
    "not_before": "...",
    "not_after": "..."
  },
  "domain": {
    "resolved_ip": "93.184.216.34"
  },
  "urlhaus": {"error": "status 401"},
  "phishtank": {"error": "status 403"},
  "score": {
    "score": 0,
    "verdict": "Likely safe",
    "breakdown": []
  }
}
```

## Caching

All external API calls are cached to reduce quota usage:
- VirusTotal: 6 hours
- Domain/WHOIS: 24 hours
- URLhaus: 1 hour
- PhishTank: 1 hour
- SSL: 12 hours

## Environment Configuration

### Required
- `VIRUSTOTAL_API_KEY`: Get from https://virustotal.com/api/

### Optional
- `PHISHTANK_API_KEY`: Get from https://phishtank.com/api/
- `FLASK_ENV`: Set to `development` for debug mode
- `FLASK_APP`: Set to `app.py`

## Getting API Keys

### VirusTotal
1. Go to https://virustotal.com/
2. Sign up (free account)
3. Navigate to API section
4. Copy your API key

### PhishTank
1. Go to https://phishtank.com/
2. Register account
3. Request API key from settings
4. Add to `.env` as `PHISHTANK_API_KEY`

## Known Limitations

- **URLhaus API Blocks**: Some networks/IPs are blocked by URLhaus (returns 401)
  - This is a service-side block, not a code issue
  - The API is correctly implemented per URLhaus documentation
  
- **PhishTank Rate Limiting**: Free tier has rate limits
  - Use API key for better rate limits
  - Results are cached to respect limits

- **VirusTotal Rate Limits**: Free tier has request/day limits
  - Caching helps reduce quota usage
  - Upgrade plan for higher limits

## Troubleshooting

**URLhaus returns 401 Unauthorized**
- This is a service-side block (IP-based filtering)
- The code follows URLhaus API docs correctly
- PhishTank API can be used as alternative if configured

**No PhishTank results**
- Set `PHISHTANK_API_KEY` in `.env` for authenticated access
- Public API has rate limits and may require authentication

**VirusTotal check fails**
- Verify `VIRUSTOTAL_API_KEY` is valid in `.env`
- Check you haven't exceeded rate limit
- Visit https://virustotal.com/api/v3/docs to verify key

**SSL Certificate errors**
- Some sites may have self-signed or invalid certificates
- These are flagged but don't prevent URL analysis

## Architecture

- **Backend**: Flask with Python 3.9+
- **External APIs**: VirusTotal v3, URLhaus, PhishTank (optional)
- **Caching**: cachetools TTLCache to reduce API calls
- **Frontend**: Vanilla JavaScript with collapsible sections
- **Port**: 5001 (default)

## Notes

- This tool does NOT use machine learning
- Results are based on heuristics + external threat databases
- Cached responses may show stale data (respect TTL settings)
- External service availability may affect accuracy

