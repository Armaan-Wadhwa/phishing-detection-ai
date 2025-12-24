import pandas as pd
import numpy as np
import math
import re
from urllib.parse import urlparse

class FeatureExtractor:
    def __init__(self):
        # Exact feature order from your notebook
        self.feature_names = [
            "url_length", "domain_length", "num_dots", "num_hyphens",
            "num_underscores", "num_slashes", "num_query_params",
            "count_digits", "has_at_symbol", "has_ip_host",
            "entropy_domain", "entropy_url"
        ]

    def _entropy(self, string):
        """Calculates Shannon entropy"""
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def extract(self, url_str):
        # Normalize URL
        if not url_str.startswith(('http://', 'https://')):
            url_str = 'http://' + url_str
            
        try:
            parsed = urlparse(url_str)
            domain = parsed.netloc
            # Strip www.
            if domain.startswith("www."):
                domain = domain[4:]
        except:
            domain = url_str

        # Feature Logic
        features = {
            "url_length": len(url_str),
            "domain_length": len(domain),
            "num_dots": url_str.count('.'),
            "num_hyphens": url_str.count('-'),
            "num_underscores": url_str.count('_'),
            "num_slashes": url_str.count('/'),
            "num_query_params": url_str.count('?'),
            "count_digits": sum(c.isdigit() for c in url_str),
            "has_at_symbol": 1 if "@" in url_str else 0,
            "has_ip_host": 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0,
            "entropy_domain": self._entropy(domain),
            "entropy_url": self._entropy(url_str)
        }

        # Return DataFrame
        return pd.DataFrame([features], columns=self.feature_names)