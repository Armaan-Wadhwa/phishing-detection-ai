import requests
from bs4 import BeautifulSoup
from typing import List, Dict
import time
from crawlers.base_crawler import BaseCrawler
from utils.validators import extract_domain_from_url
import re

class WebSearchCrawler(BaseCrawler):
    """
    Crawler using web search to find potential phishing domains
    Uses DuckDuckGo HTML (no API key required)
    """
    
    def __init__(self):
        super().__init__("web_search")
        self.search_base_url = "https://html.duckduckgo.com/html/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Search for domains related to CSE"""
        discovered = []
        
        # Generate search queries
        queries = self._generate_search_queries(target_cse)
        
        for query in queries:
            self.logger.info(f"Searching: {query}")
            
            try:
                results = self._perform_search(query)
                
                for result in results:
                    domain = extract_domain_from_url(result['url'])
                    
                    if self._is_suspicious(domain, target_cse):
                        discovered.append({
                            'domain_name': domain,
                            'url': result['url'],
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': f"web_search:{query}",
                            'raw_data': {
                                'search_query': query,
                                'result_title': result.get('title'),
                                'result_snippet': result.get('snippet')
                            }
                        })
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                self.logger.error(f"Search error for query '{query}': {e}")
                continue
        
        return discovered
    
    def _generate_search_queries(self, target_cse: Dict) -> List[str]:
        """Generate search queries to find phishing sites"""
        queries = []
        keywords = target_cse.get('keywords', [])
        primary_domain = target_cse['primary_domain']
        
        # Query patterns
        patterns = [
            f"{primary_domain} login",
            f"{primary_domain} secure",
            f"{primary_domain} verify account",
            f"{primary_domain} update payment",
            *[f"{keyword} login" for keyword in keywords],
            *[f"{keyword} banking" for keyword in keywords],
            *[f"{keyword} official site" for keyword in keywords],
        ]
        
        return patterns[:10]  # Limit queries
    
    def _perform_search(self, query: str, max_results: int = 20) -> List[Dict]:
        """Perform DuckDuckGo HTML search"""
        results = []
        
        try:
            params = {'q': query}
            response = requests.post(
                self.search_base_url,
                data=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Parse search results
            for result_div in soup.find_all('div', class_='result'):
                try:
                    link = result_div.find('a', class_='result__a')
                    snippet = result_div.find('a', class_='result__snippet')
                    
                    if link and link.get('href'):
                        results.append({
                            'url': link['href'],
                            'title': link.get_text(strip=True),
                            'snippet': snippet.get_text(strip=True) if snippet else ''
                        })
                        
                        if len(results) >= max_results:
                            break
                            
                except Exception as e:
                    self.logger.debug(f"Error parsing result: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Search request failed: {e}")
        
        return results
    
    def _is_suspicious(self, domain: str, target_cse: Dict) -> bool:
        """Check if domain is suspicious (not the legitimate CSE)"""
        if not domain:
            return False
        
        # Skip if it's the actual CSE domain
        legitimate_domains = [target_cse['primary_domain']] + target_cse.get('additional_domains', [])
        
        for legit_domain in legitimate_domains:
            if domain == legit_domain or domain.endswith(f".{legit_domain}"):
                return False
        
        # Check if domain contains CSE keywords (potential typosquat)
        keywords = target_cse.get('keywords', [])
        domain_lower = domain.lower()
        
        for keyword in keywords:
            if keyword.lower() in domain_lower:
                return True
        
        return False