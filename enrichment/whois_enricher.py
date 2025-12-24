import whois
import dns.resolver
import socket
from typing import Dict, Optional
from datetime import datetime
import logging
import time
from database.connection import get_db_session
from database.models import DiscoveredDomain


class DomainEnricher:
    """Enrich discovered domains with WHOIS and DNS data"""
    
    
    def __init__(self):
        self.logger = logging.getLogger("enricher.domain")
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 10
        self.dns_resolver.lifetime = 10
    
    def enrich_all(self, only_missing: bool = True):
        """
        Enrich discovered domains stored in DB
        """
        session = get_db_session()

        query = session.query(DiscoveredDomain)
        if only_missing:
            query = query.filter(DiscoveredDomain.whois_data.is_(None))

        domains = query.all()

        if not domains:
            self.logger.info("No domains require enrichment")
            session.close()
            return

        self.logger.info(f"Enriching {len(domains)} domains with WHOIS")

        for d in domains:
            try:
                enriched = self.enrich_domain(d.domain_name)
                d.whois_data = enriched.get("whois")
                d.dns_data = enriched.get("dns")
                d.enriched_at = enriched.get("enrichment_timestamp")

                self.logger.info(f"WHOIS enriched: {d.domain_name}")

            except Exception as e:
                self.logger.debug(f"Enrichment failed for {d.domain_name}: {e}")

        session.commit()
        session.close()
    
    def enrich_domain(self, domain: str) -> Dict:
        """Gather all available information about a domain"""
        enriched_data = {
            'domain': domain,
            'whois': self._get_whois_info(domain),
            'dns': self._get_dns_info(domain),
            'ip_info': None,
            'enrichment_timestamp': datetime.now().isoformat()
        }
        
        # Get IP information if available
        if enriched_data['dns'].get('a_records'):
            ip = enriched_data['dns']['a_records'][0]
            enriched_data['ip_info'] = self._get_ip_info(ip)
        
        return enriched_data
    
    def _get_whois_info(self, domain: str) -> Optional[Dict]:
        """Fetch WHOIS data"""
        try:
            time.sleep(1.2)  # WHOIS rate limiting
            w = whois.whois(domain)
            
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                'expiration_date': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                'updated_date': str(w.updated_date[0]) if isinstance(w.updated_date, list) else str(w.updated_date),
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                'status': w.status,
                'registrant_name': getattr(w, 'name', None),
                'registrant_org': getattr(w, 'org', None),
                'registrant_country': getattr(w, 'country', None),
                'registrant_email': getattr(w, 'emails', None)
            }
            
        except Exception as e:
            self.logger.debug(f"WHOIS failed for {domain}: {e}")
            return None
    
    def _get_dns_info(self, domain: str) -> Dict:
        """Fetch DNS records"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': []
        }
        
        record_types = {
            'A': 'a_records',
            'AAAA': 'aaaa_records',
            'MX': 'mx_records',
            'NS': 'ns_records',
            'TXT': 'txt_records',
            'CNAME': 'cname_records'
        }
        
        for record_type, key in record_types.items():
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                dns_info[key] = [str(rdata) for rdata in answers]
            except Exception:
                continue
        
        return dns_info
    
    def _get_ip_info(self, ip: str) -> Dict:
        """Get information about an IP address"""
        ip_info = {
            'ip': ip,
            'hostname': None,
            'asn': None,
            'country': None
        }
        
        try:
            # Reverse DNS
            hostname = socket.gethostbyaddr(ip)[0]
            ip_info['hostname'] = hostname
        except Exception:
            pass
        
        # For ASN/Country info, you would typically use a GeoIP database
        # or service like IPinfo, MaxMind, etc. (using local database to avoid API)
        
        return ip_info