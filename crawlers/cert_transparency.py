import certstream
import json
from typing import List, Dict
from crawlers.base_crawler import BaseCrawler
import threading
import queue
from datetime import datetime, timedelta
import time

class CertTransparencyCrawler(BaseCrawler):
    """
    Monitor Certificate Transparency logs for newly registered domains
    Real-time monitoring of SSL certificates
    """
    
    def __init__(self):
        super().__init__("cert_transparency")
        self.cert_queue = queue.Queue(maxsize=10000)
        self.stop_monitoring = False
        self.monitoring_duration = 300  # 5 minutes (reduced from 1 hour)
        self.max_retries = 3
        self.retry_count = 0
    
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """Monitor CT logs for domains matching CSE patterns"""
        discovered = []
        
        self.logger.info(f"Starting CT monitoring for {target_cse['name']} (max 5 minutes)")
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self._monitor_ct_logs,
            daemon=True
        )
        monitor_thread.start()
        
        # Process certificates for specified duration
        start_time = datetime.now()
        keywords = target_cse.get('keywords', [])
        timeout = False
        
        while (datetime.now() - start_time).seconds < self.monitoring_duration and not timeout:
            try:
                # Use timeout on queue.get to prevent infinite blocking
                cert_data = self.cert_queue.get(timeout=10)
                
                # Check all domains in certificate
                for domain in cert_data.get('all_domains', []):
                    domain_lower = domain.lower()
                    
                    # Check for keyword matches
                    for keyword in keywords:
                        if keyword.lower() in domain_lower:
                            # Verify it's not the legitimate domain
                            if not self._is_legitimate_domain(domain, target_cse):
                                discovered.append({
                                    'domain_name': domain,
                                    'url': f"https://{domain}",
                                    'target_cse_name': target_cse['name'],
                                    'target_cse_domain': target_cse['primary_domain'],
                                    'discovery_method': 'certificate_transparency',
                                    'raw_data': {
                                        'cert_issuer': cert_data.get('issuer'),
                                        'cert_not_before': cert_data.get('not_before'),
                                        'cert_not_after': cert_data.get('not_after'),
                                        'all_domains': cert_data.get('all_domains')
                                    },
                                    'is_idn': self._is_idn_domain(domain)
                                })
                                break
                
            except queue.Empty:
                # No certificates received in 10 seconds
                self.logger.warning("No CT data received for 10 seconds")
                if (datetime.now() - start_time).seconds > 30:
                    # If we've been running for 30+ seconds with no data, stop
                    self.logger.warning("CT stream appears inactive, stopping early")
                    timeout = True
                continue
                
            except Exception as e:
                self.logger.error(f"Error processing certificate: {e}")
        
        self.stop_monitoring = True
        monitor_thread.join(timeout=5)  # Wait max 5 seconds for thread to finish
        
        self.logger.info(f"CT monitoring completed. Found {len(discovered)} domains")
        
        return discovered
    
    def _monitor_ct_logs(self):
        """Monitor CT logs and queue certificates"""
        def callback(message, context):
            if self.stop_monitoring:
                return
            
            message_type = message.get('message_type')
            
            if message_type == "certificate_update":
                try:
                    cert_data = {
                        'all_domains': message['data']['leaf_cert']['all_domains'],
                        'issuer': message['data']['leaf_cert']['issuer'].get('CN', 'Unknown'),
                        'not_before': message['data']['leaf_cert'].get('not_before'),
                        'not_after': message['data']['leaf_cert'].get('not_after')
                    }
                    
                    if not self.cert_queue.full():
                        self.cert_queue.put(cert_data)
                    
                    # Reset retry count on successful message
                    self.retry_count = 0
                        
                except Exception as e:
                    self.logger.debug(f"Error processing cert message: {e}")
        
        # Try connecting with retries
        while self.retry_count < self.max_retries and not self.stop_monitoring:
            try:
                self.logger.info(f"Connecting to CertStream (attempt {self.retry_count + 1}/{self.max_retries})...")
                certstream.listen_for_events(
                    callback, 
                    url='wss://certstream.calidog.io/',
                    skip_heartbeats=True
                )
                
            except Exception as e:
                self.retry_count += 1
                self.logger.error(f"CT connection failed (attempt {self.retry_count}): {e}")
                
                if self.retry_count < self.max_retries:
                    sleep_time = 5 * self.retry_count  # Exponential backoff
                    self.logger.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    self.logger.error("Max retries reached. Giving up on CT monitoring.")
                    self.stop_monitoring = True
                    break
    
    def _is_legitimate_domain(self, domain: str, target_cse: Dict) -> bool:
        """Check if domain belongs to legitimate CSE"""
        legitimate_domains = [target_cse['primary_domain']] + target_cse.get('additional_domains', [])
        
        for legit in legitimate_domains:
            if domain == legit or domain.endswith(f".{legit}"):
                return True
        
        return False
    
    def _is_idn_domain(self, domain: str) -> bool:
        """Check if domain contains non-ASCII characters (IDN)"""
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True