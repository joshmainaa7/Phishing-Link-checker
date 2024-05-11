import tldextract
import Levenshtein as lv

legit_domains = [('example', 'com'), ('google', 'com'), ('facebook', 'com')]

test_urls = [
    'http://www.example.com',
    'http://www.google.com',
    'http://www.facebo0k.com',
    'http://www.y0utube.com',
    'http://www.wikipedia.co.ke',
    'http://www.yaho0.com'
]

def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix

def is_misspelled_domain(domain, legit_domains, threshold=0.9):
    for legit_domain in legit_domains:
        similarity = lv.ratio(domain, legit_domain[0])
        if similarity >= threshold:
            return False  # legit domain
    return True  # no close match found

def is_phishing_url(url, legit_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    # check if it's a known legitimate domain
    if (domain, suffix) in legit_domains:
        return False

    # check for misspelled domain names
    if is_misspelled_domain(domain, [legit_domain[0] for legit_domain in legit_domains]):
        print(f"Potential phishing detected: {url}")
        return True

    # adding more checks like suspicious subdomains
    return False

if __name__ == '__main__':
    for url in test_urls:
        if is_phishing_url(url, legit_domains):
            continue
