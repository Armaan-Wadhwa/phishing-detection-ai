from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class DiscoveredDomain(Base):
    __tablename__ = 'discovered_domains'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Domain Information
    domain_name = Column(String(255), nullable=False, unique=True, index=True)
    url = Column(Text, nullable=True)
    
    # CSE Targeting
    target_cse_name = Column(String(255), nullable=False, index=True)
    target_cse_domain = Column(String(255), nullable=False)
    
    # Classification (to be filled in Phase 2)
    classification = Column(String(50), nullable=True)  # phishing/suspected/legitimate
    confidence_score = Column(Integer, nullable=True)
    
    # Discovery Metadata
    source_of_detection = Column(String(100), nullable=False, index=True)
    discovery_date = Column(DateTime, default=func.now(), nullable=False, index=True)
    discovery_method = Column(String(100), nullable=True)
    
    # Domain Registration Data
    domain_creation_date = Column(DateTime, nullable=True)
    domain_expiration_date = Column(DateTime, nullable=True)
    domain_updated_date = Column(DateTime, nullable=True)
    registrar_name = Column(String(255), nullable=True)
    registrant_name = Column(String(255), nullable=True)
    registrant_organization = Column(String(255), nullable=True)
    registrant_country = Column(String(100), nullable=True)
    
    # DNS & Hosting
    name_servers = Column(JSON, nullable=True)
    hosting_ip = Column(String(45), nullable=True)
    hosting_isp = Column(String(255), nullable=True)
    hosting_country = Column(String(100), nullable=True)
    hosting_asn = Column(String(50), nullable=True)
    dns_records = Column(JSON, nullable=True)  # A, MX, TXT records
    
    # SSL/Certificate
    has_ssl = Column(Boolean, default=False)
    ssl_issuer = Column(String(255), nullable=True)
    ssl_valid_from = Column(DateTime, nullable=True)
    ssl_valid_to = Column(DateTime, nullable=True)
    cert_transparency_logs = Column(JSON, nullable=True)
    
    # Content Analysis (basic metadata)
    is_active = Column(Boolean, default=False)
    http_status_code = Column(Integer, nullable=True)
    page_title = Column(Text, nullable=True)
    favicon_hash = Column(String(64), nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    
    # IDN Detection
    is_idn = Column(Boolean, default=False)
    idn_original = Column(String(255), nullable=True)
    
    # Monitoring
    last_checked = Column(DateTime, default=func.now(), onupdate=func.now())
    monitoring_status = Column(String(50), default='pending')  # pending/active/inactive
    
    # Additional Metadata
    remarks = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)  # Store all raw data for future analysis
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_discovery_date', 'discovery_date'),
        Index('idx_target_source', 'target_cse_domain', 'source_of_detection'),
        Index('idx_monitoring', 'monitoring_status', 'last_checked'),
    )


class CrawlerLog(Base):
    __tablename__ = 'crawler_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    crawler_name = Column(String(100), nullable=False, index=True)
    start_time = Column(DateTime, default=func.now())
    end_time = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False)  # running/completed/failed
    domains_discovered = Column(Integer, default=0)
    errors_encountered = Column(Integer, default=0)
    error_details = Column(JSON, nullable=True)
    crawler_metadata = Column(JSON, nullable=True)  # CHANGED: renamed from 'metadata'
    created_at = Column(DateTime, default=func.now())