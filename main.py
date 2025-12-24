#!/usr/bin/env python3
import logging
import sys
import click
import pandas as pd
from datetime import datetime
from sqlalchemy import func

# --- Project Imports ---
from config.settings import Config
from database.connection import init_database, get_db_session
from database.models import DiscoveredDomain

# --- Component Imports ---
# 1. Crawlers (Your existing modules)
from crawlers.web_search import WebSearchCrawler
from crawlers.whois_crawler import WHOISCrawler
from crawlers.cert_transparency import CertTransparencyCrawler
from crawlers.social_media import SocialMediaCrawler
from crawlers.paste_sites import PasteSitesCrawler
from crawlers.tunnel_services import TunnelServicesCrawler
from crawlers.dorking_crawler import DorkingCrawler
from enrichment.whois_enricher import DomainEnricher

# 2. New ML & Evidence Engines
from ml_engine.predictor import PhishingPredictor
from evidence.screenshotter import EvidenceCollector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(Config.LOGS_DIR / f'system_{datetime.now().strftime("%Y%m%d")}.log')
    ]
)
logger = logging.getLogger("Orchestrator")

class PhishingDetectorOrchestrator:
    """
    Master controller for the Phishing Detection Pipeline:
    Phase 1: Discovery (Crawling)
    Phase 2: Analysis (ML Classification)
    Phase 3: Evidence (Screenshots)
    """
    
    def __init__(self):
        self.config = Config()
        # Initialize Crawlers
        self.crawlers = self._initialize_crawlers()
        self.enricher = DomainEnricher()
        
        # Initialize Engines (Lazy loading to save resources if not needed)
        self._ml_predictor = None
        self._evidence_collector = None

    @property
    def ml_predictor(self):
        if not self._ml_predictor:
            # Assumes best_model.joblib is in models/
            self._ml_predictor = PhishingPredictor() 
        return self._ml_predictor

    @property
    def evidence_collector(self):
        if not self._evidence_collector:
            self._evidence_collector = EvidenceCollector()
        return self._evidence_collector

    def _initialize_crawlers(self):
        """Initialize enabled crawler modules based on settings.py"""
        crawlers = []
        if Config.ENABLE_WEB_SEARCH: crawlers.append(WebSearchCrawler())
        if Config.ENABLE_WHOIS: crawlers.append(WHOISCrawler())
        if Config.ENABLE_CERT_TRANSPARENCY: crawlers.append(CertTransparencyCrawler())
        if Config.ENABLE_SOCIAL_MEDIA: crawlers.append(SocialMediaCrawler())
        if Config.ENABLE_PASTE_SITES: crawlers.append(PasteSitesCrawler())
        if Config.ENABLE_TUNNEL_DETECTION: crawlers.append(TunnelServicesCrawler())
        if Config.ENABLE_DORKING: crawlers.append(DorkingCrawler())
        
        logger.info(f"Initialized {len(crawlers)} discovery modules")
        return crawlers

    # --- PHASE 1: DISCOVERY ---
    def run_discovery(self, manual_target=None):
        """
        Run all crawlers.
        args:
            manual_target: Optional dict to override cse_targets.yaml for a specific scan.
        """
        targets = [manual_target] if manual_target else Config.load_cse_targets()
        
        logger.info("="*60)
        logger.info(f" STARTING PHASE 1: DISCOVERY ({len(targets)} targets)")
        logger.info("="*60)
        
        total_found = 0
        for crawler in self.crawlers:
            try:
                logger.info(f"Running {crawler.name}...")
                summary = crawler.run(targets)
                count = summary.get('domains_found', 0)
                total_found += count
                logger.info(f"  [+] {crawler.name}: Found {count} domains")
            except Exception as e:
                logger.error(f"  [!] {crawler.name} Failed: {e}")
        
        logger.info(f"Discovery Complete. Total candidates found: {total_found}")
        return total_found

    # --- PHASE 2: ML ANALYSIS ---
    def run_ml_analysis(self):
        """
        Fetch unclassified domains from DB and run them through the ML model.
        """
        session = get_db_session()
        
        # 1. Get Pending Domains
        domains = session.query(DiscoveredDomain).filter(
            DiscoveredDomain.classification.is_(None)
        ).all()
        
        if not domains:
            logger.info("No unclassified domains found. Skipping ML Phase.")
            session.close()
            return

        logger.info("="*60)
        logger.info(f" STARTING PHASE 2: ML ANALYSIS ({len(domains)} domains)")
        logger.info("="*60)

        # 2. Predict Loop
        phishing_count = 0
        for domain in domains:
            try:
                # Feature Extraction & Prediction happens inside Predictor
                label, conf = self.ml_predictor.predict(domain.domain_name)
                
                # Update DB Record
                domain.classification = label
                domain.confidence_score = int(conf * 100) # Save as 0-100
                
                if label in ['Phishing', 'Suspected']:
                    phishing_count += 1
                    logger.warning(f"  [!] DETECTED: {domain.domain_name} -> {label} ({conf:.2f})")
                else:
                    logger.info(f"  [+] Clean: {domain.domain_name} ({conf:.2f})")
                    
            except Exception as e:
                logger.error(f"  [X] ML Error for {domain.domain_name}: {e}")

        session.commit()
        session.close()
        logger.info(f"ML Analysis Complete. Identified {phishing_count} potential threats.")

    # --- PHASE 3: EVIDENCE COLLECTION ---
    def run_evidence_collection(self):
        """
        Take screenshots of confirmed/suspected phishing domains.
        """
        session = get_db_session()
        
        # 1. Get Targets (Phishing/Suspected AND No Screenshot yet)
        targets = session.query(DiscoveredDomain).filter(
            DiscoveredDomain.classification.in_(['Phishing', 'Suspected']),
            DiscoveredDomain.screenshot_path.is_(None)
        ).all()
        
        if not targets:
            logger.info("No threats requiring evidence. Skipping Phase 3.")
            session.close()
            return

        logger.info("="*60)
        logger.info(f" STARTING PHASE 3: EVIDENCE COLLECTION ({len(targets)} targets)")
        logger.info("="*60)

        collected_count = 0
        for domain in targets:
            try:
                logger.info(f"Snapshotting: {domain.domain_name}")
                
                # Use URL if available, else construct http://domain
                target_url = domain.url if domain.url else domain.domain_name
                
                path = self.evidence_collector.capture_screenshot(target_url, domain.domain_name)
                
                if path:
                    domain.screenshot_path = path
                    # Optional: domain.monitoring_status = 'verified'
                    collected_count += 1
                    logger.info(f"  ✓ Saved to: {path}")
                else:
                    logger.warning(f"  ✗ Failed to capture {domain.domain_name}")
                    
            except Exception as e:
                logger.error(f"  ✗ Evidence Error: {e}")

        session.commit()
        session.close()
        logger.info(f"Evidence Collection Complete. {collected_count} screenshots saved.")

    # --- REPORTING ---
    def export_report(self, filename=None):
        """Generate final CSV report"""
        if not filename:
            filename = Config.DATA_DIR / f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        
        session = get_db_session()
        domains = session.query(DiscoveredDomain).all()
        
        data = []
        for d in domains:
            data.append({
                "Domain": d.domain_name,
                "Target CSE": d.target_cse_name,
                "Source": d.source_of_detection,
                "ML Classification": d.classification,
                "Confidence": d.confidence_score,
                "Screenshot": d.screenshot_path,
                "Discovery Date": d.discovery_date
            })
        
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        session.close()
        logger.info(f" Report exported to: {filename}")
        return filename

# --- CLI COMMANDS ---

@click.group()
def cli():
    """Phishing Detection System - End-to-End Pipeline"""
    pass

@cli.command()
def init_db():
    """Initialize Database Tables"""
    Config.ensure_directories()
    init_database()

@cli.command()
def discover():
    """Run Only Phase 1: Discovery Crawlers"""
    orch = PhishingDetectorOrchestrator()
    orch.run_discovery()

@cli.command()
def analyze():
    """Run Only Phase 2: ML Classification on existing data"""
    orch = PhishingDetectorOrchestrator()
    orch.run_ml_analysis()

@cli.command()
def evidence():
    """Run Only Phase 3: Evidence Collection on classified threats"""
    orch = PhishingDetectorOrchestrator()
    orch.run_evidence_collection()

@cli.command()
@click.option('--name', help='Target CSE Name (e.g. "HDFC Bank")')
@click.option('--domain', help='Official Domain (e.g. "hdfcbank.com")')
@click.option('--keywords', help='Keywords (comma separated)')
def scan(name, domain, keywords):
    """
    Run the FULL End-to-End Pipeline for a specific target.
    Discovery -> ML -> Evidence -> Report
    """
    Config.ensure_directories()
    init_database()
    
    # Construct target object dynamically
    if name and domain:
        target = {
            "name": name,
            "primary_domain": domain,
            "keywords": keywords.split(',') if keywords else [],
            "additional_domains": []
        }
    else:
        target = None # Use default YAML config
    
    orch = PhishingDetectorOrchestrator()
    
    # 1. Discovery
    orch.run_discovery(manual_target=target)
    
    # 2. Enrichment (Whois)
    orch.enricher.enrich_all() # Optional, if you want full whois data before ML
    
    # 3. ML Analysis
    orch.run_ml_analysis()
    
    # 4. Evidence
    orch.run_evidence_collection()
    
    # 5. Report
    orch.export_report()

if __name__ == '__main__':
    cli()