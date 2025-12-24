# ui/db_utils.py
from sqlalchemy import create_engine
import pandas as pd
import os

DB_USER = "postgres"
DB_PASSWORD = "poiuuiop"
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "phishing_detector"


DATABASE_URL = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

engine = create_engine(DATABASE_URL)


def get_latest_scan_domains():
    query = """
    WITH latest_scan AS (
        SELECT start_time
        FROM crawler_logs
        ORDER BY start_time DESC
        LIMIT 1
    )
    SELECT d.*
    FROM discovered_domains d, latest_scan ls
    WHERE d.discovery_date >= ls.start_time
      AND d.discovery_date <= ls.start_time + INTERVAL '10 minutes'
    ORDER BY d.discovery_date DESC;
    """
    return pd.read_sql(query, engine)





def get_latest_evidence():
    query = """
    SELECT domain_name, screenshot_path
    FROM discovered_domains
    WHERE screenshot_path IS NOT NULL
    ORDER BY discovery_date DESC;
    """
    return pd.read_sql(query, engine)

