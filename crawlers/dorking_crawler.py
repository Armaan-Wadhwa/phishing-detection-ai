from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from typing import List, Dict, Set
import time
import random
import re
from crawlers.base_crawler import BaseCrawler
from utils.validators import extract_domain_from_url, is_valid_domain
from datetime import datetime

class DorkingCrawler(BaseCrawler):
    """
    Google Dorking crawler using Playwright
    Searches for potential phishing domains using advanced search operators
    """
    
    def __init__(self):
        super().__init__("dorking")
        self.search_engines = {
            'bing': 'https://www.bing.com/search?q=',
            'duckduckgo': 'https://duckduckgo.com/?q=',
            'google': 'https://www.google.com/search?q='
        }
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        self.results_per_engine = 20
        self.delay_between_searches = (10, 20)  # Random delay in seconds
        self.google_query_limit = 3     # max Google dorks per run
        self.google_enabled = True
    
    def _build_search_url(self, engine: str, query: str) -> str:
        if engine == "google":
            return f"https://www.google.com/search?q={query}"
        elif engine == "bing":
            return f"https://www.bing.com/search?q={query}"
        elif engine == "duckduckgo":
            return f"https://duckduckgo.com/?q={query}&ia=web"
        else:
            raise ValueError(f"Unknown engine: {engine}")

    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Execute dorking search for CSE (Bing/DDG-first, Google-limited)"""
        discovered = []

        primary_domain = target_cse['primary_domain']
        keywords = target_cse.get('keywords', [])

        self.logger.info(f"Starting dorking search for {target_cse['name']}")

        # Generate dork queries
        dork_queries = self._generate_dork_queries(primary_domain, keywords)
        self.logger.info(f"Generated {len(dork_queries)} dork queries")

        google_used = 0

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
            )

            context = browser.new_context(
                user_agent=random.choice(self.user_agents),
                viewport={'width': 1920, 'height': 1080}
            )

            page = context.new_page()

            try:
                # 🔥 ENGINE PRIORITY: Bing → DuckDuckGo → Google
                for query in dork_queries:
                    self.logger.info(f"Executing dork: {query[:80]}...")

                    # ---------------- BING ---------------- #
                    results_bing = self._search_bing(page, query, target_cse)
                    discovered.extend(results_bing)

                    time.sleep(random.uniform(*self.delay_between_searches))

                    # ---------------- DUCKDUCKGO ---------------- #
                    results_ddg = self._search_duckduckgo(page, query, target_cse)
                    discovered.extend(results_ddg)

                    time.sleep(random.uniform(*self.delay_between_searches))

                    # ---------------- GOOGLE (LIMITED) ---------------- #
                    if self.google_enabled and google_used < self.google_query_limit:
                        results_google = self._search_google(page, query, target_cse)

                        # CAPTCHA handling (Google only)
                        if not results_google:
                            self.logger.warning(
                                "Google returned no results (possible CAPTCHA). Disabling Google."
                            )
                            self.google_enabled = False
                        else:
                            discovered.extend(results_google)
                            google_used += 1

                        time.sleep(random.uniform(*self.delay_between_searches))
                    else:
                        if not self.google_enabled:
                            self.logger.info("Google disabled due to CAPTCHA detection")
                        elif google_used >= self.google_query_limit:
                            self.logger.info("Google query limit reached")

            finally:
                browser.close()

        self.logger.info(
            f"Dorking completed. Found {len(discovered)} potential domains "
            f"(Google used {google_used}/{self.google_query_limit})"
        )

        return discovered

    
    def _generate_dork_queries(self, primary_domain: str, keywords: List[str]) -> List[str]:
        """Generate Google dork queries"""
        dorks = []
        
        # Extract main keyword from domain (e.g., "hdfc" from "hdfcbank.com")
        domain_parts = primary_domain.replace('.', ' ').split()
        main_keyword = domain_parts[0] if domain_parts else ""
        
        # Add all CSE keywords
        all_keywords = list(set([main_keyword] + keywords))
        
        for keyword in all_keywords:
            # 1. Find login pages with keyword
            dorks.append(f'inurl:login "{keyword}"')
            dorks.append(f'intitle:login "{keyword}"')
            
            # 2. Find similar domains (typosquatting)
            dorks.append(f'inurl:{keyword} -site:{primary_domain}')
            
            # 3. Find phishing-related terms
            dorks.append(f'"{keyword}" intitle:"verify account"')
            dorks.append(f'"{keyword}" intitle:"update payment"')
            dorks.append(f'"{keyword}" intitle:"suspended account"')
            dorks.append(f'"{keyword}" inurl:secure')
            dorks.append(f'"{keyword}" inurl:banking')
            dorks.append(f'"{keyword}" inurl:netbanking')
            
            # 4. Find similar looking domains
            dorks.append(f'inurl:{keyword}bank -site:{primary_domain}')
            dorks.append(f'inurl:{keyword}online -site:{primary_domain}')
            
            # # 5. Find pages mentioning phishing
            # dorks.append(f'"{keyword}" phishing site')
            # dorks.append(f'"{keyword}" fake website')
            # dorks.append(f'"{keyword}" scam alert')
            
            # 6. Find Certificate Transparency logs mentions
            dorks.append(f'site:crt.sh "{keyword}"')
            
            # 7. Find suspicious file types
            dorks.append(f'"{keyword}" filetype:html inurl:login')
            
            # 8. Find on free hosting platforms
            dorks.append(f'"{keyword}" site:000webhost.com')
            dorks.append(f'"{keyword}" site:weebly.com')
            dorks.append(f'"{keyword}" site:wordpress.com')
            
            # 9. Find on URL shorteners (expanded)
            dorks.append(f'"{keyword}" site:bit.ly')
            dorks.append(f'"{keyword}" site:tinyurl.com')
            
            # 10. Find with common phishing patterns
            dorks.append(f'inurl:{keyword} inurl:verify')
            dorks.append(f'inurl:{keyword} inurl:confirm')
            dorks.append(f'inurl:{keyword} inurl:account')
        
        # Limit total queries to avoid rate limiting
        return dorks[:30]  # Top 30 queries
    
    def _extract_results(self, page, engine: str):
        links = []

        if engine == "google":
            elements = page.query_selector_all("a h3")
            for el in elements:
                href = el.evaluate("node => node.parentElement.href")
                if href:
                    links.append(href)

        elif engine == "bing":
            elements = page.query_selector_all("li.b_algo h2 a")
            for el in elements:
                href = el.get_attribute("href")
                if href:
                    links.append(href)

        elif engine == "duckduckgo":
            elements = page.query_selector_all("a.result__a")
            for el in elements:
                href = el.get_attribute("href")
                if href:
                    links.append(href)

        return links

    def _search_google(self, page, query: str, target_cse: Dict) -> List[Dict]:
        """Perform Google search and extract results"""
        discovered = []
        search_url = f"https://www.google.com/search?q={query}&num=20"
        
        try:
            # Navigate to Google search
            page.goto(search_url, wait_until='domcontentloaded', timeout=45000)
            
            # Wait for results
            page.wait_for_selector('div#search', timeout=10000)
            
            # Extract search result links
            results = page.query_selector_all('div.g')
            
            for result in results[:self.results_per_engine]:
                try:
                    # Extract URL
                    link_element = result.query_selector('a')
                    if not link_element:
                        continue
                    
                    url = link_element.get_attribute('href')
                    if not url or not url.startswith('http'):
                        continue
                    
                    # Extract title and snippet
                    title_element = result.query_selector('h3')
                    title = title_element.inner_text() if title_element else ""
                    
                    snippet_element = result.query_selector('div.VwiC3b')
                    snippet = snippet_element.inner_text() if snippet_element else ""
                    
                    # Extract domain
                    domain = extract_domain_from_url(url)
                    
                    if not domain or not is_valid_domain(domain):
                        continue
                    
                    # Check if it's suspicious (not the official domain)
                    if self._is_suspicious_domain(domain, target_cse):
                        discovered.append({
                            'domain_name': domain,
                            'url': url,
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': f'google_dork:{query[:50]}',
                            'raw_data': {
                                'search_query': query,
                                'result_title': title,
                                'result_snippet': snippet,
                                'search_engine': 'google'
                            }
                        })
                        
                        self.logger.info(f"  Found: {domain}")
                
                except Exception as e:
                    self.logger.debug(f"Error parsing result: {e}")
                    continue
            
            # Check for CAPTCHA
            if 'captcha' in page.content().lower():
                self.logger.warning("CAPTCHA detected — skipping Google dorking")
                return []
        
        except PlaywrightTimeout:
            self.logger.error(f"Timeout loading search results for: {query}")
        except Exception as e:
            self.logger.error(f"Error searching Google: {e}")
        
        return discovered
    
    def _search_bing(self, page, query: str, target_cse: Dict) -> List[Dict]:
        """Perform Bing search and extract results"""
        discovered = []
        search_url = f"https://www.bing.com/search?q={query}&count=20"
        
        try:
            page.goto(search_url, wait_until='domcontentloaded', timeout=45000)
            page.wait_for_selector('#b_results', timeout=20000)
            
            # Extract results
            results = page.query_selector_all('li.b_algo')
            
            for result in results[:self.results_per_engine]:
                try:
                    link_element = result.query_selector('h2 a')
                    if not link_element:
                        continue
                    
                    url = link_element.get_attribute('href')
                    if not url or not url.startswith('http'):
                        continue
                    
                    title = link_element.inner_text()
                    
                    snippet_element = result.query_selector('p')
                    snippet = snippet_element.inner_text() if snippet_element else ""
                    
                    domain = extract_domain_from_url(url)
                    
                    if domain and is_valid_domain(domain) and self._is_suspicious_domain(domain, target_cse):
                        discovered.append({
                            'domain_name': domain,
                            'url': url,
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': f'bing_dork:{query[:50]}',
                            'raw_data': {
                                'search_query': query,
                                'result_title': title,
                                'result_snippet': snippet,
                                'search_engine': 'bing'
                            }
                        })
                
                except Exception as e:
                    self.logger.debug(f"Error parsing Bing result: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error searching Bing: {e}")
        
        return discovered
    
    def _search_duckduckgo(self, page, query: str, target_cse: Dict) -> List[Dict]:
        """Perform DuckDuckGo search and extract results"""
        discovered = []
        search_url = f"https://duckduckgo.com/?q={query}"
        
        try:
            page.goto(search_url, wait_until='domcontentloaded', timeout=45000)
            page.wait_for_selector('article[data-testid="result"]', timeout=20000)
            
            results = page.query_selector_all('article[data-testid="result"]')
            
            for result in results[:self.results_per_engine]:
                try:
                    link_element = result.query_selector('a[data-testid="result-title-a"]')
                    if not link_element:
                        continue
                    
                    url = link_element.get_attribute('href')
                    if not url or not url.startswith('http'):
                        continue
                    
                    title = link_element.inner_text()
                    
                    snippet_element = result.query_selector('div[data-result="snippet"]')
                    snippet = snippet_element.inner_text() if snippet_element else ""
                    
                    domain = extract_domain_from_url(url)
                    
                    if domain and is_valid_domain(domain) and self._is_suspicious_domain(domain, target_cse):
                        discovered.append({
                            'domain_name': domain,
                            'url': url,
                            'target_cse_name': target_cse['name'],
                            'target_cse_domain': target_cse['primary_domain'],
                            'discovery_method': f'ddg_dork:{query[:50]}',
                            'raw_data': {
                                'search_query': query,
                                'result_title': title,
                                'result_snippet': snippet,
                                'search_engine': 'duckduckgo'
                            }
                        })
                
                except Exception as e:
                    self.logger.debug(f"Error parsing DDG result: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error searching DuckDuckGo: {e}")
        
        return discovered
    
    def _is_suspicious_domain(self, domain: str, target_cse: Dict) -> bool:
        """Check if domain is suspicious (not official CSE domain)"""
        if not domain:
            return False
        
        # Skip official domains
        legitimate_domains = [target_cse['primary_domain']] + target_cse.get('additional_domains', [])
        
        domain_lower = domain.lower()
        for legit in legitimate_domains:
            if domain_lower == legit.lower() or domain_lower.endswith(f".{legit.lower()}"):
                return False
        
        # Check if domain contains CSE keywords (potential phishing)
        keywords = target_cse.get('keywords', [])
        for keyword in keywords:
            if keyword.lower() in domain_lower:
                return True
        
        return False