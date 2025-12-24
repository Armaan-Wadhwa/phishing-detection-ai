import itertools
from typing import List, Set
import tldextract

class TyposquatGenerator:
    """Generate typosquatting and lookalike domain variants"""
    
    # Common TLDs for phishing
    COMMON_TLDS = [
        'com', 'net', 'org', 'info', 'co', 'in', 'co.in',
        'xyz', 'top', 'online', 'site', 'club', 'live',
        'tech', 'store', 'website', 'space', 'pro'
    ]
    
    # Character substitutions (visual similarity)
    CHAR_SUBSTITUTIONS = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', 'l', '!'],
        'l': ['1', 'i'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7'],
        'g': ['9'],
        'b': ['8'],
    }
    
    # Common keyboard typos (adjacent keys)
    KEYBOARD_ADJACENCY = {
        'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
        'e': 'wsdr', 'f': 'drtgvc', 'g': 'ftyhhbv', 'h': 'gyujnb',
        'i': 'ujko', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
        'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
        'q': 'wa', 'r': 'edf t', 's': 'awedxz', 't': 'rfgy',
        'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
        'y': 'tghu', 'z': 'asx'
    }
    
    @staticmethod
    def extract_domain_parts(domain: str) -> dict:
        """Extract subdomain, domain, and TLD"""
        extracted = tldextract.extract(domain)
        return {
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix
        }
    
    def generate_all_variants(self, domain: str, max_variants: int = 1000) -> Set[str]:
        """Generate all typosquatting variants"""
        variants = set()
        parts = self.extract_domain_parts(domain)
        base_domain = parts['domain']
        original_tld = parts['suffix']
        
        # 1. Character omission
        variants.update(self._character_omission(base_domain, original_tld))
        
        # 2. Character repetition
        variants.update(self._character_repetition(base_domain, original_tld))
        
        # 3. Character replacement (substitution)
        variants.update(self._character_substitution(base_domain, original_tld))
        
        # 4. Character insertion
        variants.update(self._character_insertion(base_domain, original_tld))
        
        # 5. Character swap (transposition)
        variants.update(self._character_swap(base_domain, original_tld))
        
        # 6. Keyboard typos
        variants.update(self._keyboard_typos(base_domain, original_tld))
        
        # 7. Homograph attacks (visual similarity)
        variants.update(self._homograph_variants(base_domain, original_tld))
        
        # 8. TLD variations
        variants.update(self._tld_variations(base_domain))
        
        # 9. Hyphenation
        variants.update(self._hyphenation(base_domain, original_tld))
        
        # 10. Common prefixes/suffixes
        variants.update(self._prefix_suffix(base_domain, original_tld))
        
        # Limit variants
        if len(variants) > max_variants:
            variants = set(list(variants)[:max_variants])
        
        return variants
    
    def _character_omission(self, domain: str, tld: str) -> Set[str]:
        """Remove one character at a time"""
        variants = set()
        for i in range(len(domain)):
            variant = domain[:i] + domain[i+1:]
            if len(variant) >= 3:  # Minimum domain length
                variants.add(f"{variant}.{tld}")
        return variants
    
    def _character_repetition(self, domain: str, tld: str) -> Set[str]:
        """Double each character"""
        variants = set()
        for i in range(len(domain)):
            variant = domain[:i] + domain[i] + domain[i:]
            variants.add(f"{variant}.{tld}")
        return variants
    
    def _character_substitution(self, domain: str, tld: str) -> Set[str]:
        """Replace characters with lookalikes"""
        variants = set()
        for i, char in enumerate(domain):
            if char.lower() in self.CHAR_SUBSTITUTIONS:
                for replacement in self.CHAR_SUBSTITUTIONS[char.lower()]:
                    variant = domain[:i] + replacement + domain[i+1:]
                    variants.add(f"{variant}.{tld}")
        return variants
    
    def _character_insertion(self, domain: str, tld: str) -> Set[str]:
        """Insert characters"""
        variants = set()
        for i in range(len(domain) + 1):
            for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
                variant = domain[:i] + char + domain[i:]
                if len(variant) <= 63:  # Max domain label length
                    variants.add(f"{variant}.{tld}")
        return variants
    
    def _character_swap(self, domain: str, tld: str) -> Set[str]:
        """Swap adjacent characters"""
        variants = set()
        for i in range(len(domain) - 1):
            chars = list(domain)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variant = ''.join(chars)
            variants.add(f"{variant}.{tld}")
        return variants
    
    def _keyboard_typos(self, domain: str, tld: str) -> Set[str]:
        """Replace with adjacent keyboard keys"""
        variants = set()
        for i, char in enumerate(domain):
            if char.lower() in self.KEYBOARD_ADJACENCY:
                for adjacent in self.KEYBOARD_ADJACENCY[char.lower()]:
                    variant = domain[:i] + adjacent + domain[i+1:]
                    variants.add(f"{variant}.{tld}")
        return variants
    
    def _homograph_variants(self, domain: str, tld: str) -> Set[str]:
        """Visual similarity attacks (basic)"""
        homographs = {
            'o': ['0', 'ο', 'о'],  # Latin o, digit 0, Greek omicron, Cyrillic o
            'a': ['а', 'α'],        # Latin a, Cyrillic a, Greek alpha
            'e': ['е', 'ε'],        # Latin e, Cyrillic e, Greek epsilon
            'i': ['і', 'ι'],        # Latin i, Cyrillic i, Greek iota
            'p': ['р', 'ρ'],        # Latin p, Cyrillic r, Greek rho
            'c': ['с', 'ϲ'],        # Latin c, Cyrillic s, Greek lunate sigma
            'y': ['у', 'γ'],        # Latin y, Cyrillic u, Greek gamma
        }
        
        variants = set()
        for i, char in enumerate(domain):
            if char.lower() in homographs:
                for replacement in homographs[char.lower()]:
                    variant = domain[:i] + replacement + domain[i+1:]
                    variants.add(f"{variant}.{tld}")
        return variants
    
    def _tld_variations(self, domain: str) -> Set[str]:
        """Try different TLDs"""
        variants = set()
        for tld in self.COMMON_TLDS:
            variants.add(f"{domain}.{tld}")
        return variants
    
    def _hyphenation(self, domain: str, tld: str) -> Set[str]:
        """Add hyphens"""
        variants = set()
        for i in range(1, len(domain)):
            variant = domain[:i] + '-' + domain[i:]
            variants.add(f"{variant}.{tld}")
        return variants
    
    def _prefix_suffix(self, domain: str, tld: str) -> Set[str]:
        """Add common prefixes/suffixes"""
        prefixes = ['', 'www', 'secure', 'login', 'account', 'verify', 'update']
        suffixes = ['', 'login', 'secure', 'online', 'bank', 'auth', 'verify']
        
        variants = set()
        for prefix in prefixes:
            for suffix in suffixes:
                if prefix or suffix:  # At least one must be present
                    parts = [p for p in [prefix, domain, suffix] if p]
                    variant = '-'.join(parts)
                    variants.add(f"{variant}.{tld}")
        
        return variants