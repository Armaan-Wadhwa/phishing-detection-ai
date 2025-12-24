from typing import Set, List

class IDNGenerator:
    """Generate Internationalized Domain Name (IDN) homograph attacks"""
    
    # Homograph character mappings
    HOMOGRAPHS = {
        'a': ['а', 'ɑ', 'α', 'ａ'],  # Cyrillic а, Latin alpha, Greek alpha, fullwidth
        'b': ['Ь', 'ᖯ', 'ｂ'],
        'c': ['с', 'ϲ', 'ⅽ', 'ｃ'],  # Cyrillic с, Greek lunate sigma
        'd': ['ԁ', 'ⅾ', 'ｄ'],
        'e': ['е', 'ė', 'ε', 'ｅ'],  # Cyrillic е, Greek epsilon
        'f': ['f', 'ｆ'],
        'g': ['ɡ', 'ɢ', 'ｇ'],
        'h': ['һ', 'Һ', 'ｈ'],
        'i': ['і', 'ι', 'ⅰ', 'ｉ'],  # Cyrillic і, Greek iota
        'j': ['ј', 'ⅉ', 'ｊ'],
        'k': ['κ', 'к', 'ｋ'],  # Greek kappa, Cyrillic к
        'l': ['ⅼ', 'Ⅰ', 'ｌ'],
        'm': ['m', 'ⅿ', 'ｍ'],
        'n': ['n', 'ո', 'ｎ'],
        'o': ['о', 'ο', 'σ', '০', 'ｏ'],  # Cyrillic о, Greek omicron
        'p': ['р', 'ρ', 'ⲣ', 'ｐ'],  # Cyrillic р, Greek rho
        'q': ['q', 'ԛ', 'ｑ'],
        'r': ['r', 'г', 'ｒ'],
        's': ['ѕ', 'ʂ', 'ｓ'],
        't': ['t', 'т', 'ｔ'],
        'u': ['u', 'υ', 'ս', 'ｕ'],  # Greek upsilon
        'v': ['v', 'ν', 'ѵ', 'ｖ'],  # Greek nu
        'w': ['w', 'ԝ', 'ｗ'],
        'x': ['x', 'х', 'ⅹ', 'ｘ'],  # Cyrillic х
        'y': ['y', 'у', 'ү', 'ｙ'],  # Cyrillic у
        'z': ['z', 'ᴢ', 'ｚ'],
    }
    
    @classmethod
    def generate_idn_variants(cls, domain: str, max_variants: int = 100) -> Set[str]:
        """Generate IDN homograph variants"""
        variants = set()
        
        # Extract domain parts
        parts = domain.split('.')
        if len(parts) < 2:
            return variants
        
        domain_name = parts[0]
        tld = '.'.join(parts[1:])
        
        # Generate single character substitutions
        for i, char in enumerate(domain_name.lower()):
            if char in cls.HOMOGRAPHS:
                for homograph in cls.HOMOGRAPHS[char]:
                    variant = domain_name[:i] + homograph + domain_name[i+1:]
                    variants.add(f"{variant}.{tld}")
                    
                    if len(variants) >= max_variants:
                        return variants
        
        # Generate multi-character substitutions (limited)
        for i in range(len(domain_name)):
            for j in range(i+1, min(i+3, len(domain_name))):  # Max 2 chars
                if domain_name[i].lower() in cls.HOMOGRAPHS and domain_name[j].lower() in cls.HOMOGRAPHS:
                    for h1 in cls.HOMOGRAPHS[domain_name[i].lower()][:2]:
                        for h2 in cls.HOMOGRAPHS[domain_name[j].lower()][:2]:
                            variant = (domain_name[:i] + h1 + 
                                     domain_name[i+1:j] + h2 + 
                                     domain_name[j+1:])
                            variants.add(f"{variant}.{tld}")
                            
                            if len(variants) >= max_variants:
                                return variants
        
        return variants