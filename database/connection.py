from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
from config.settings import Config
from database.models import Base
import logging

logger = logging.getLogger(__name__)

# Create engine with connection pooling
engine = create_engine(
    Config.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=False
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ScopedSession = scoped_session(SessionLocal)


def init_database():
    """Initialize database tables"""
    logger.info("Initializing database...")
    Base.metadata.create_all(bind=engine)
    logger.info(" Database tables created successfully")


def get_db_session():
    """Get a new database session"""
    return SessionLocal()


def close_session():
    """Close scoped session"""
    ScopedSession.remove()