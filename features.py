import re
import math
import tldextract
from urllib.parse import urlparse

def calculate_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_features(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Assume https by default for naked domains

    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    
    # 1. url_length
    url_length = len(url)
    
    # 2. has_ip_address
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    
    # 3. dot_count
    dot_count = url.count('.')
    
    # 4. https_flag
    https_flag = 1 if parsed_url.scheme == 'https' else 0
    
    # 5. url_entropy
    url_entropy = calculate_entropy(url)
    
    # 6. token_count (tokens separated by ., /, ?, =, -, _)
    tokens = re.split(r'\.|\/|\?|\=|\-|\_', url)
    token_count = len([t for t in tokens if t])
    
    # 7. subdomain_count
    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    
    # 8. query_param_count
    query_param_count = len(parsed_url.query.split('&')) if parsed_url.query else 0
    
    # 9. tld_length
    tld_length = len(ext.suffix)
    
    # 10. path_length
    path_length = len(parsed_url.path)
    
    # 11. has_hyphen_in_domain
    has_hyphen = 1 if '-' in ext.domain else 0
    
    # 12. number_of_digits
    num_digits = sum(c.isdigit() for c in url)
    
    # 13. tld_popularity (Simulated: 1 for common TLDs, 0 for rare)
    common_tlds = ['com', 'org', 'net', 'edu', 'gov']
    tld_popularity = 1 if ext.suffix in common_tlds else 0
    
    # 14. suspicious_file_extension
    suspicious_exts = ['.exe', '.php', '.js', '.zip', '.rar', '.bat']
    has_suspicious = 1 if any(url.endswith(ext) for ext in suspicious_exts) else 0
    
    # 15. domain_name_length
    domain_length = len(ext.domain)
    
    # 16. percentage_numeric_chars
    pct_numeric = (num_digits / url_length) if url_length > 0 else 0
    
    return {
        "url_length": url_length,
        "has_ip_address": has_ip,
        "dot_count": dot_count,
        "https_flag": https_flag,
        "url_entropy": url_entropy,
        "token_count": token_count,
        "subdomain_count": subdomain_count,
        "query_param_count": query_param_count,
        "tld_length": tld_length,
        "path_length": path_length,
        "has_hyphen_in_domain": has_hyphen,
        "number_of_digits": num_digits,
        "tld_popularity": tld_popularity,
        "suspicious_file_extension": has_suspicious,
        "domain_name_length": domain_length,
        "percentage_numeric_chars": pct_numeric
    }