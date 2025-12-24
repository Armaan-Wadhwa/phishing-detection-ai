import requests
from bs4 import BeautifulSoup
from typing import List, Dict
import re
from crawlers.base_crawler import BaseCrawler
from utils.validators import extract_domain_from_url
import time

class SocialMediaCrawler(BaseCrawler):
    """
    Crawl public social media for shared phishing links
    Focus: Twitter/X, Facebook public pages (no API)
    """
    
    def __init__(self):
        super().__init__("social_media")
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Search social media for phishing reports"""
        discovered = []
        
        keywords = target_cse.get('keywords', [])
        
        # Search patterns
        search_terms = [
            f"{kw} phishing" for kw in keywords
        ] + [
            f"{kw} scam" for kw in keywords
        ] + [
            f"{kw} fake site" for kw in keywords
        ]
        
        for term in search_terms[:5]:  # Limit searches
            self.logger.info(f"Searching social media for: {term}")
            
            try:
                # Search via Google (social media results)
                urls = self._search_social_mentions(term)
                
                for url in urls:
                    domain = extract_domain_from_url(url)
                    
                    if domain and self._is_suspicious_domain(domain, target_cse):
                        discovered.append({
                            'domain_name': domain,
                            'url': url,
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': f'social_media:{term}',
                            'raw_data': {
                                'search_term': term,
                                'source': 'social_media_mention'
                            }
                        })
                
                time.sleep(3)  # Rate limiting
                
            except Exception as e:
                self.logger.error(f"Social media search error: {e}")
                continue
        
        return discovered
    
    def _search_social_mentions(self, query: str) -> List[str]:
        """Search for social media mentions containing URLs"""
        urls = []
        
        try:
            # Use DuckDuckGo to find social media posts
            search_query = f"{query} site:twitter.com OR site:facebook.com"
            
            # Simplified search (you can enhance with actual scraping)
            # For production, consider using official APIs or RSS feeds
            
            # Placeholder: In real implementation, scrape search results
            # and extract URLs from posts
            
        except Exception as e:
            self.logger.error(f"Social search failed: {e}")
        
        return urls
    
    def _is_suspicious_domain(self, domain: str, target_cse: Dict) -> bool:
        """Check if domain is potentially malicious"""
        if not domain:
            return False
        
        # Skip legitimate domains
        legitimate = [target_cse['primary_domain']] + target_cse.get('additional_domains', [])
        
        for legit in legitimate:
            if domain == legit or domain.endswith(f".{legit}"):
                return False
        
        # Check for keyword presence
        keywords = target_cse.get('keywords', [])
        domain_lower = domain.lower()
        
        return any(kw.lower() in domain_lower for kw in keywords)