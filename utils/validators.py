import re
from urllib.parse import urlparse

def extract_domain_from_url(url: str) -> str:
    """Extracts the domain (netloc) from a URL string."""
    if not url:
        return None
    
    # Ensure protocol exists for urlparse to work correctly
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urlparse(url)
        # Remove port if present (e.g., example.com:8080 -> example.com)
        return parsed.netloc.split(':')[0].lower()
    except Exception:
        return None

def is_valid_domain(domain: str) -> bool:
    """Checks if a string looks like a valid domain name."""
    if not domain or len(domain) > 255:
        return False
    
    # Regex for standard domain validation
    # 1. Allowed chars: a-z, 0-9, hyphen
    # 2. Cannot start/end with hyphen
    # 3. TLD must be 2-63 chars
    domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
    
    return bool(re.match(domain_regex, domain))

def normalize_domain(domain: str) -> str:
    """Normalizes a domain string (lowercase, stripped)."""
    if not domain:
        return ""
    return domain.strip().lower()