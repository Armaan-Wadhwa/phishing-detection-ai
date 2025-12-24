import requests
from typing import List, Dict
from crawlers.base_crawler import BaseCrawler
import re

class TunnelServicesCrawler(BaseCrawler):
    """
    Detect phishing sites using tunneling services
    Services: Ngrok, Vercel, Cloudflare Tunnel, etc.
    """
    
    def __init__(self):
        super().__init__("tunnel_services")
        self.tunnel_patterns = [
            r'.*\.ngrok\.io',
            r'.*\.ngrok-free\.app',
            r'.*\.vercel\.app',
            r'.*\.herokuapp\.com',
            r'.*\.repl\.co',
            r'.*\.glitch\.me',
            r'.*\.pages\.dev',
            r'.*\.web\.app',
            r'.*\.trycloudflare\.com',
        ]
        self.compiled_patterns = [re.compile(p) for p in self.tunnel_patterns]
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Search for tunnel service domains mimicking CSE"""
        discovered = []
        
        keywords = target_cse.get('keywords', [])
        
        # Generate potential tunnel URLs
        for keyword in keywords:
            for pattern in self.tunnel_patterns:
                # Example: sbi-login.ngrok.io
                base_domain = pattern.split(r'\.')[1:]
                domain_suffix = '.'.join([p.replace('\\', '') for p in base_domain])
                
                test_domains = [
                    f"{keyword.lower()}-login.{domain_suffix}",
                    f"{keyword.lower()}-secure.{domain_suffix}",
                    f"{keyword.lower()}-verify.{domain_suffix}",
                    f"{keyword.lower()}online.{domain_suffix}",
                ]
                
                for test_domain in test_domains:
                    if self._domain_is_active(test_domain):
                        discovered.append({
                            'domain_name': test_domain,
                            'url': f"https://{test_domain}",
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': 'tunnel_service_detection',
                            'raw_data': {
                                'tunnel_service': domain_suffix,
                                'keyword_used': keyword
                            }
                        })
        
        return discovered
    
    def _domain_is_active(self, domain: str) -> bool:
        """Check if tunnel domain is active"""
        try:
            response = requests.head(
                f"https://{domain}",
                timeout=10,
                allow_redirects=True,
                verify=False  # Tunnel services may have cert issues
            )
            return response.status_code < 500
            
        except Exception:
            return False