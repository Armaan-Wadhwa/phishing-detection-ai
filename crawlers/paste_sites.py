import requests
from bs4 import BeautifulSoup
from typing import List, Dict
import re
from crawlers.base_crawler import BaseCrawler
from utils.validators import extract_domain_from_url
import time
import certifi
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PasteSitesCrawler(BaseCrawler):
    """
    Monitor paste sites for leaked/shared phishing URLs
    Sources: Pastebin, Ghostbin, etc.
    """
    
    def __init__(self):
        super().__init__("paste_sites")
        self.paste_sites = [
            'https://pastebin.com/archive',
            'https://ghostbin.com/browse',
        ]
        self.url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Crawl recent pastes for phishing URLs"""
        discovered = []
        
        keywords = target_cse.get('keywords', [])
        
        for paste_url in self.paste_sites:
            self.logger.info(f"Checking paste site: {paste_url}")
            
            try:
                recent_pastes = self._get_recent_pastes(paste_url)
                
                for paste in recent_pastes:
                    content = self._get_paste_content(paste['url'])
                    
                    if content:
                        # Check if content mentions CSE keywords
                        content_lower = content.lower()
                        keyword_match = any(kw.lower() in content_lower for kw in keywords)
                        
                        if keyword_match:
                            # Extract URLs from paste
                            urls = self.url_pattern.findall(content)
                            
                            for url in urls:
                                domain = extract_domain_from_url(url)
                                
                                if domain and self._is_suspicious_domain(domain, target_cse):
                                    discovered.append({
                                        'domain_name': domain,
                                        'url': url,
                                        'target_cse_name': target_cse['name'],
                                        'target_cse_domain': target_cse['primary_domain'],
                                        'discovery_method': 'paste_site',
                                        'raw_data': {
                                            'paste_url': paste['url'],
                                            'paste_title': paste.get('title'),
                                            'paste_date': paste.get('date')
                                        }
                                    })
                
                time.sleep(5)  # Respect rate limits
                
            except Exception as e:
                self.logger.error(f"Error crawling paste site {paste_url}: {e}")
                continue
        
        return discovered
    
    def _get_recent_pastes(self, archive_url: str, limit: int = 50) -> List[Dict]:
        """Get list of recent pastes"""
        pastes = []
        
        try:
            response = requests.get(archive_url, headers={
                'User-Agent': 'Mozilla/5.0'
            }, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Parse based on site (Pastebin example)
            if 'pastebin.com' in archive_url:
                for row in soup.find_all('tr', class_='')[:limit]:
                    link = row.find('a')
                    if link:
                        pastes.append({
                            'url': f"https://pastebin.com{link['href']}",
                            'title': link.text.strip()
                        })
            
        except Exception as e:
            self.logger.error(f"Error fetching paste archive: {e}")
        
        return pastes
    
    def _get_paste_content(self, paste_url: str) -> str:
        """Fetch content of a specific paste"""
        try:
            # Convert to raw URL
            if 'pastebin.com' in paste_url:
                paste_id = paste_url.split('/')[-1]
                raw_url = f"https://pastebin.com/raw/{paste_id}"
            else:
                raw_url = paste_url
            
            response = requests.get(raw_url, headers={
                'User-Agent': 'Mozilla/5.0'
            }, timeout=30,verify=certifi.where())
            response.raise_for_status()
            
            return response.text
            
        except Exception as e:
            self.logger.debug(f"Error fetching paste content: {e}")
            return ""
    
    def _is_suspicious_domain(self, domain: str, target_cse: Dict) -> bool:
        """Check if domain is suspicious"""
        if not domain:
            return False
        
        legitimate = [target_cse['primary_domain']] + target_cse.get('additional_domains', [])
        
        for legit in legitimate:
            if domain == legit or domain.endswith(f".{legit}"):
                return False
        
        keywords = target_cse.get('keywords', [])
        domain_lower = domain.lower()
        
        return any(kw.lower() in domain_lower for kw in keywords)