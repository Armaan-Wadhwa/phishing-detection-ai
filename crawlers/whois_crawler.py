import whois
import dns.resolver
from typing import List, Dict, Optional
from crawlers.base_crawler import BaseCrawler
from generators.typosquat import TyposquatGenerator
import socket
from datetime import datetime, timedelta

class WHOISCrawler(BaseCrawler):
    """
    Check WHOIS data for generated typosquat domains
    Identifies newly registered domains
    """
    
    def __init__(self):
        super().__init__("whois")
        self.typo_generator = TyposquatGenerator()
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Check typosquat variants via WHOIS"""
        discovered = []
        
        primary_domain = target_cse['primary_domain']
        self.logger.info(f"Generating typosquat variants for {primary_domain}")
        
        # Generate variants
        variants = self.typo_generator.generate_all_variants(
            primary_domain,
            max_variants=150  # Limit for reasonable execution time
        )
        
        self.logger.info(f"Generated {len(variants)} variants. Checking registration...")
        
        for i, variant_domain in enumerate(variants):
            if i % 50 == 0:
                self.logger.info(f"Progress: {i}/{len(variants)} domains checked")
            
            try:
                # Check if domain resolves (faster than WHOIS)
                if self._domain_exists(variant_domain):
                    whois_data = self._get_whois_data(variant_domain)
                    
                    if whois_data:
                        # Check if recently registered
                        if self._is_recently_registered(whois_data):
                            discovered.append({
                                'domain_name': variant_domain,
                                'url': f"http://{variant_domain}",
                                'target_cse_name': target_cse['name'],
                                'target_cse_domain': primary_domain,
                                'discovery_method': 'whois_typosquat',
                                'raw_data': {
                                    'whois': whois_data,
                                    'generation_method': 'typosquatting'
                                }
                            })
                
            except Exception as e:
                self.logger.debug(f"Error checking {variant_domain}: {e}")
                continue
        
        self.logger.info(f"WHOIS check completed. Found {len(discovered)} registered variants")
        return discovered
    
    def _domain_exists(self, domain: str) -> bool:
        """Check if domain has DNS records"""
        try:
            # Try A record
            self.dns_resolver.resolve(domain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            # Domain exists but no A record - still interesting
            return True
        except Exception:
            return False
    def _safe_parse(self, value):
        try:
            return self._parse_whois_date(value)
        except Exception:
            return None

    def _get_whois_data(self, domain: str) -> Optional[Dict]:
        """Fetch WHOIS data for domain"""
        try:
            time.sleep(1.2)
            w = whois.whois(domain)
            
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': self._safe_parse(getattr(w, 'creation_date', None)),
                'expiration_date': self._safe_parse(getattr(w, 'expiration_date', None)),
                'updated_date': self._safe_parse(getattr(w, 'updated_date', None)),
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                'status': w.status,
                'registrant_name': getattr(w, 'name', None),
                'registrant_org': getattr(w, 'org', None),
                'registrant_country': getattr(w, 'country', None)
            }
            
        except Exception as e:
            self.logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return None
    
    def _parse_whois_date(self, date_value) -> Optional[str]:
        """Parse WHOIS date (can be string, datetime, or list)"""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        
        return str(date_value)
    
    def _is_recently_registered(self, whois_data: Dict, days: int = 90) -> bool:
        """Check if domain was registered recently"""
        creation_date = whois_data.get('creation_date')
        
        if not creation_date:
            return True  # Unknown age - flag for review
        
        try:
            if isinstance(creation_date, str):
                created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            else:
                created = creation_date
            
            age = datetime.now() - created.replace(tzinfo=None)
            return age.days <= days
            
        except Exception:
            return True  # Can't determine age - flag for review