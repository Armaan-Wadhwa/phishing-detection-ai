import os
from pathlib import Path
from typing import List, Dict
import yaml
from dotenv import load_dotenv
load_dotenv()

class Config:
    # Project Paths
    BASE_DIR = Path(__file__).parent.parent
    CONFIG_DIR = BASE_DIR / "config"
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"
    
    # Database
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "phishing_detector")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "poiuuiop")
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    
    # Redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))
    
    # Crawler Settings
    CONCURRENT_REQUESTS = 10
    REQUEST_TIMEOUT = 30
    MAX_RETRIES = 3
    RATE_LIMIT_DELAY = 1  # seconds between requests
    USER_AGENT = "PhishingDetectorBot/1.0 (Research Purpose)"
    
    # Detection Parameters
    MONITOR_SUSPECTED_DURATION_DAYS = 90  # 3 months
    DOMAIN_AGE_THRESHOLD_DAYS = 30  # Flag domains < 30 days old
    
    # Data Sources
    ENABLE_WEB_SEARCH = True
    ENABLE_WHOIS = True
    ENABLE_CERT_TRANSPARENCY = True
    ENABLE_SOCIAL_MEDIA = True
    ENABLE_PASTE_SITES = True
    ENABLE_TUNNEL_DETECTION = True
    ENABLE_DORKING = True 
    
    @classmethod
    def load_cse_targets(cls) -> List[Dict]:
        """Load CSE domains from YAML configuration"""
        cse_file = cls.CONFIG_DIR / "cse_targets.yaml"
        with open(cse_file, 'r') as f:
            return yaml.safe_load(f)['cse_entities']
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories"""
        for directory in [cls.DATA_DIR, cls.LOGS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)