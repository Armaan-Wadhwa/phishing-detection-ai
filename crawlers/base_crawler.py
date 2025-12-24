from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import logging
from datetime import datetime
import hashlib
from database.models import DiscoveredDomain, CrawlerLog
from database.connection import get_db_session
from utils.validators import is_valid_domain, normalize_domain
from utils.rate_limiter import RateLimiter

class BaseCrawler(ABC):
    """Abstract base class for all crawlers"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"crawler.{name}")
        self.rate_limiter = RateLimiter(calls=10, period=60)
        self.domains_found = []
        self.log_id = None
        
    def start_logging(self):
        """Initialize crawler log entry"""
        session = get_db_session()
        log_entry = CrawlerLog(
            crawler_name=self.name,
            status='running',
            start_time=datetime.now()
        )
        session.add(log_entry)
        session.commit()
        self.log_id = log_entry.id
        session.close()
        
    def end_logging(self, status: str, errors: List[str] = None):
        """Finalize crawler log entry"""
        if not self.log_id:
            return
            
        session = get_db_session()
        log_entry = session.query(CrawlerLog).filter_by(id=self.log_id).first()
        if log_entry:
            log_entry.end_time = datetime.now()
            log_entry.status = status
            log_entry.domains_discovered = len(self.domains_found)
            log_entry.errors_encountered = len(errors) if errors else 0
            log_entry.error_details = {'errors': errors} if errors else None
            session.commit()
        session.close()
    
    @abstractmethod
    def crawl(self, target_cse: Dict) -> List[Dict]:
        """
        Main crawling method to be implemented by subclasses
        
        Args:
            target_cse: Dictionary containing CSE information
            
        Returns:
            List of discovered domain dictionaries
        """
        pass
    
    def save_domain(self, domain_data: Dict) -> bool:
        """
        Save discovered domain to database with deduplication
        
        Args:
            domain_data: Dictionary with domain information
            
        Returns:
            True if saved successfully, False if duplicate
        """
        try:
            # Normalize domain
            domain_name = normalize_domain(domain_data.get('domain_name'))
            
            if not is_valid_domain(domain_name):
                self.logger.warning(f"Invalid domain: {domain_name}")
                return False
            
            session = get_db_session()
            
            # Check for duplicate
            existing = session.query(DiscoveredDomain).filter_by(
                domain_name=domain_name
            ).first()
            
            if existing:
                self.logger.debug(f"Duplicate domain skipped: {domain_name}")
                session.close()
                return False
            
            # Create new entry
            domain_entry = DiscoveredDomain(
                domain_name=domain_name,
                url=domain_data.get('url'),
                target_cse_name=domain_data.get('target_cse_name'),
                target_cse_domain=domain_data.get('target_cse_domain'),
                source_of_detection=self.name,
                discovery_method=domain_data.get('discovery_method'),
                raw_data=domain_data.get('raw_data'),
                is_idn=domain_data.get('is_idn', False),
                idn_original=domain_data.get('idn_original')
            )
            
            session.add(domain_entry)
            session.commit()
            session.close()
            
            self.domains_found.append(domain_name)
            self.logger.info(f"Saved new domain: {domain_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving domain {domain_data.get('domain_name')}: {e}")
            return False
    
    def run(self, cse_targets: List[Dict]) -> Dict:
        """
        Execute crawler for all CSE targets
        
        Args:
            cse_targets: List of CSE configurations
            
        Returns:
            Summary dictionary
        """
        self.start_logging()
        errors = []
        
        try:
            for cse in cse_targets:
                self.logger.info(f"Crawling for CSE: {cse['name']}")
                
                try:
                    with self.rate_limiter:
                        discovered = self.crawl(cse)
                        
                        for domain_data in discovered:
                            self.save_domain(domain_data)
                            
                except Exception as e:
                    error_msg = f"Error crawling {cse['name']}: {str(e)}"
                    self.logger.error(error_msg)
                    errors.append(error_msg)
            
            self.end_logging('completed', errors)
            
        except Exception as e:
            self.logger.critical(f"Critical error in crawler: {e}")
            self.end_logging('failed', [str(e)])
            raise
        
        return {
            'crawler': self.name,
            'domains_found': len(self.domains_found),
            'cses_processed': len(cse_targets),
            'errors': len(errors)
        }