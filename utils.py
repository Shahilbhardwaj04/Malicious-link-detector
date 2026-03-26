import re
import ipaddress
import time
import requests
from urllib.parse import urlparse
import socket
import ssl
import json
try:
    import whois
except Exception:
    whois = None
from cachetools import TTLCache, cached

# Caches
vt_cache = TTLCache(maxsize=1000, ttl=60 * 60 * 6)
whois_cache = TTLCache(maxsize=1000, ttl=60 * 60 * 24)
urlhaus_cache = TTLCache(maxsize=1000, ttl=60 * 60)
phishtank_cache = TTLCache(maxsize=1000, ttl=60 * 60)
ssl_cache = TTLCache(maxsize=1000, ttl=60 * 60 * 12)
score_cache = TTLCache(maxsize=10000, ttl=60 * 60)

VT_BASE = "https://www.virustotal.com/api/v3"


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def analyze_url(url):
    """Return heuristic indicators for a given URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        return {'error': 'Invalid URL format'}
        
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    heuristics = {}
    heuristics['uses_https'] = parsed.scheme.lower() == 'https'
    heuristics['has_at_symbol'] = '@' in url
    heuristics['long_url'] = len(url) > 75
    heuristics['ip_in_domain'] = is_ip_address(hostname)
    heuristics['suspicious_chars'] = bool(re.search(r"[%<>\\\\]", url))
    heuristics['has_double_slash_in_path'] = '//' in path
    heuristics['host_length'] = len(hostname)
    heuristics['num_subdomains'] = hostname.count('.')
    heuristics['uses_punycode'] = hostname.startswith('xn--') if hostname else False
    
    # New Heuristics
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'signin', 'wp-admin', 'billing']
    heuristics['has_malicious_keywords'] = any(kw in url.lower() for kw in keywords)
    heuristics['multiple_extensions'] = bool(re.search(r'\.(php|html|asp|aspx)\.(exe|zip|scr|msi|bat)$', url.lower()))
    heuristics['shortened_url'] = any(s in hostname.lower() for s in ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly'])

    return heuristics


def virus_total_check(url, api_key, timeout=15):
    """Submit URL to VirusTotal (v3) and retrieve analysis summary.

    Returns a dict summary or raises an exception on error.
    """
    headers = {"x-apikey": api_key}

    # Submit URL for analysis
    resp = requests.post(f"{VT_BASE}/urls", data={"url": url}, headers=headers, timeout=10)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"VirusTotal submit failed: {resp.status_code} {resp.text}")

    data = resp.json().get('data', {})
    analysis_id = data.get('id')
    if not analysis_id:
        raise RuntimeError('No analysis id returned from VirusTotal')

    # Poll analysis endpoint until finished or timeout
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"VirusTotal analysis fetch failed: {r.status_code} {r.text}")
        j = r.json()
        status = j.get('data', {}).get('attributes', {}).get('status')
        if status == 'completed':
            stats = j.get('data', {}).get('attributes', {}).get('stats', {})
            return {
                'analysis_id': analysis_id,
                'status': status,
                'stats': stats,
                'raw': j
            }
        time.sleep(1)

    raise RuntimeError('VirusTotal analysis timed out')


def get_ssl_info(url, timeout=5):
    """Return basic SSL certificate information for the host, or None if not available."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 443)
    if not host:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                return {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'raw': cert
                }
    except Exception as e:
        return {'error': str(e)}


def get_domain_reputation(url):
    """Return basic domain info: IP, registrar (if whois available), and nameservers."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    info = {}
    try:
        ip = socket.gethostbyname(host)
        info['resolved_ip'] = ip
    except Exception as e:
        info['resolved_ip_error'] = str(e)

    if whois:
        try:
            w = whois.whois(host)
            # convert to JSON-serializable
            info['whois'] = {}
            for k, v in w.items():
                try:
                    json.dumps(v)
                    info['whois'][k] = v
                except Exception:
                    info['whois'][k] = str(v)
        except Exception as e:
            info['whois_error'] = str(e)
            # RDAP fallback will be attempted below if whois fails

    return info


@cached(whois_cache, key=lambda url: url)
def cached_get_domain_reputation(url):
    """Cached wrapper around get_domain_reputation with RDAP fallback if whois fails."""
    info = get_domain_reputation(url)
    # if whois_error present or whois missing, try RDAP
    if (not info.get('whois')) and (not whois or info.get('whois_error')):
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            try:
                r = requests.get(f'https://rdap.org/domain/{host}', timeout=10)
                if r.status_code == 200:
                    j = r.json()
                    rdap_info = {}
                    rdap_info['name'] = j.get('ldhName') or j.get('handle')
                    events = j.get('events') or []
                    for ev in events:
                        if ev.get('eventAction') == 'registration':
                            rdap_info['creation_date'] = ev.get('eventDate')
                        if ev.get('eventAction') == 'expiration':
                            rdap_info['expiration_date'] = ev.get('eventDate')
                    rdap_info['nameservers'] = [n.get('ldhName') for n in j.get('nameservers', []) if isinstance(n, dict)]
                    info['whois_rdap'] = rdap_info
            except Exception as e:
                info['whois_rdap_error'] = str(e)
    return info


def check_urlhaus(url):
    """Query URLhaus public API for URL details.
    
    URLhaus provides free, unauthenticated access to malware URL lookups.
    No API key required for basic access.
    
    Returns dict with query results or error info.
    """
    try:
        headers = {
            'User-Agent': 'Phishing-Link-Detector/1.0 (+https://github.com/)',
            'Accept': 'application/json'
        }
        
        # Try URL endpoint first
        r = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            headers=headers,
            timeout=10
        )
        
        if r.status_code == 200:
            result = r.json()
            if result.get('query_status') == 'ok':
                return result
            return result
        
        # If URL endpoint fails, try host endpoint as fallback
        parsed = urlparse(url)
        host = parsed.hostname
        if host and r.status_code in [401, 403]:
            r = requests.post(
                'https://urlhaus-api.abuse.ch/v1/host/',
                data={'host': host},
                headers=headers,
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
        
        return {'error': f'status {r.status_code}', 'text': r.text[:200] if r.text else 'No response body'}
    except requests.exceptions.Timeout:
        return {'error': 'timeout', 'message': 'URLhaus API timeout'}
    except Exception as e:
        return {'error': type(e).__name__, 'message': str(e)}


@cached(urlhaus_cache, key=lambda url: url)
def cached_check_urlhaus(url):
    return check_urlhaus(url)


def check_phishtank(url, api_key=None):
    """Check PhishTank using public or authenticated API.
    
    PhishTank public API: https://phishtank.com/api_info.php
    For reliable results, an API key is recommended.
    """
    try:
        endpoint = 'https://checkurl.phishtank.com/checkurl/'
        data = {'url': url, 'format': 'json'}
        
        # Add API key if available for better rate limiting
        if api_key:
            data['app_key'] = api_key
        
        # Add User-Agent to avoid blocks
        headers = {'User-Agent': 'Phishing-Link-Detector/1.0'}
        r = requests.post(endpoint, data=data, headers=headers, timeout=10)
        
        if r.status_code == 200:
            try:
                result = r.json()
                # Parse PhishTank response
                if result.get('results'):
                    return {
                        'in_database': result.get('in_database', False),
                        'valid': result.get('valid', False),
                        'verified': result.get('verified', False),
                        'phish_id': result.get('phish_id'),
                        'phish_detail_url': result.get('phish_detail_url'),
                        'submission_time': result.get('submission_time'),
                        'verified_time': result.get('verified_time'),
                        'target': result.get('target'),
                        'raw': result
                    }
                return result
            except:
                return {'error': 'json_parse', 'raw_response': r.text[:200]}
        elif r.status_code == 429:
            return {'error': 'rate_limited', 'message': 'PhishTank API rate limited'}
        else:
            return {'error': f'status {r.status_code}', 'message': 'PhishTank API error'}
    except requests.exceptions.Timeout:
        return {'error': 'timeout', 'message': 'PhishTank check timed out'}
    except Exception as e:
        return {'error': type(e).__name__, 'message': str(e)}


@cached(phishtank_cache, key=lambda url, api_key=None: url)
def cached_check_phishtank(url, api_key=None):
    return check_phishtank(url, api_key)


@cached(ssl_cache, key=lambda url, timeout=5: url)
def cached_get_ssl_info(url, timeout=5):
    return get_ssl_info(url, timeout=timeout)


@cached(vt_cache, key=lambda url, api_key, timeout=15: url)
def cached_virus_total_check(url, api_key, timeout=15):
    if not api_key:
        return None
    return virus_total_check(url, api_key, timeout=timeout)


def compute_risk_score(heuristics, vt_result=None, urlhaus=None, phishtank=None, domain=None, ssl_info=None):
    """Compute a weighted risk score and return a breakdown and verdict.

    Returns: {score:int, verdict:str, breakdown:list}
    """
    score = 0
    breakdown = []

    # Heuristics weights
    h_weights = {
        'ip_in_domain': 5,
        'has_at_symbol': 3,
        'long_url': 1,
        'suspicious_chars': 2,
        'has_double_slash_in_path': 2,
        'uses_punycode': 4,
        'has_malicious_keywords': 3,
        'multiple_extensions': 6,
        'shortened_url': 2
    }
    for k, w in h_weights.items():
        if heuristics.get(k):
            score += w
            breakdown.append({'signal': k, 'points': w, 'detail': heuristics.get(k)})

    # Scheme check
    if not heuristics.get('uses_https'):
        score += 2
        breakdown.append({'signal': 'unsecured_http', 'points': 2, 'detail': False})

    # subdomain and host length
    try:
        if heuristics.get('num_subdomains', 0) >= 3:
            score += 1
            breakdown.append({'signal': 'num_subdomains', 'points': 1, 'detail': heuristics.get('num_subdomains')})
        if heuristics.get('host_length', 0) > 30:
            score += 1
            breakdown.append({'signal': 'host_length', 'points': 1, 'detail': heuristics.get('host_length')})
    except Exception:
        pass

    # VirusTotal stats
    if vt_result and isinstance(vt_result, dict):
        stats = vt_result.get('stats') or {}
        mal = int(stats.get('malicious', 0) or 0)
        sus = int(stats.get('suspicious', 0) or 0)
        if mal:
            pts = mal * 5
            score += pts
            breakdown.append({'signal': 'virustotal_malicious', 'points': pts, 'detail': mal})
        if sus:
            pts = sus * 2
            score += pts
            breakdown.append({'signal': 'virustotal_suspicious', 'points': pts, 'detail': sus})

    # URLhaus
    try:
        if urlhaus and isinstance(urlhaus, dict):
            if urlhaus.get('query_status') == 'ok' and urlhaus.get('data'):
                pts = 20
                score += pts
                breakdown.append({'signal': 'urlhaus_listed', 'points': pts, 'detail': len(urlhaus.get('data'))})
    except Exception:
        pass

    # PhishTank
    try:
        if phishtank and isinstance(phishtank, dict):
            # Check different possible response structures
            in_db = phishtank.get('in_database') or \
                   (phishtank.get('results') or {}).get('in_database') or \
                   (phishtank.get('result') or {}).get('in_database')
            
            if in_db:
                pts = 20
                score += pts
                detail = phishtank.get('phish_id') or phishtank.get('target') or 'PhishTank database match'
                breakdown.append({'signal': 'phishtank_listed', 'points': pts, 'detail': detail})
    except Exception:
        pass

    # Domain age from whois
    try:
        if domain and isinstance(domain, dict):
            who = domain.get('whois') or {}
            creation = who.get('creation_date') or who.get('created')
            if creation:
                from datetime import datetime
                def to_dt(val):
                    if isinstance(val, list):
                        val = val[0]
                    if hasattr(val, 'isoformat'):
                        return val
                    for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y'):
                        try:
                            return datetime.strptime(str(val), fmt)
                        except Exception:
                            continue
                    return None

                dt = to_dt(creation)
                if dt:
                    age_days = (datetime.utcnow() - dt).days
                    if age_days < 30:
                        score += 5
                        breakdown.append({'signal': 'domain_age', 'points': 5, 'detail': f'{age_days}d'})
                    elif age_days < 180:
                        score += 2
                        breakdown.append({'signal': 'domain_age', 'points': 2, 'detail': f'{age_days}d'})
    except Exception:
        pass

    # SSL checks
    try:
        if ssl_info:
            if isinstance(ssl_info, dict) and ssl_info.get('error'):
                score += 5
                breakdown.append({'signal': 'ssl_error', 'points': 5, 'detail': ssl_info.get('error')})
            else:
                not_after = None
                try:
                    na = ssl_info.get('not_after')
                    from datetime import datetime
                    if na:
                        try:
                            not_after = datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                        except Exception:
                            pass
                    if not_after:
                        days_left = (not_after - datetime.utcnow()).days
                        if days_left < 7:
                            score += 3
                            breakdown.append({'signal': 'ssl_expires_soon', 'points': 3, 'detail': f'{days_left}d'})
                except Exception:
                    pass
    except Exception:
        pass

    # final verdict thresholds
    verdict = 'Likely safe'
    if score >= 20:
        verdict = 'Malicious'
    elif score >= 8:
        verdict = 'Suspicious'

    return {'score': score, 'verdict': verdict, 'breakdown': breakdown}
