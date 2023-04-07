import re
import csv
import requests
from urllib.parse import urlparse
from tld import get_tld, update_tld_names

# Get user input
campaign_name = input('Enter a campaign name: ')
urls = input('Enter a list of URLs to scrape, separated by commas: ').split(',')
excluded_domains = input('Enter a comma-separated list of domain names to be excluded(blank when none): ').split(',')
csv_filename = input('Enter a filename for the CSV: ')

# Update the TLD list
update_tld_names()

# Variables to store the results
hashes = []
ip_addresses = []
domain_names = []

for url in urls:
    # Scrape the URL
    url_domain = urlparse(url.strip()).hostname

    response = requests.get(url.strip())
    text = response.text
    
    # Find all hashes in the page text
    md5_hashes = re.findall(r'\b[a-fA-F\d]{32}\b', text)
    sha1_hashes = re.findall(r'\b[a-fA-F\d]{40}\b', text)
    sha256_hashes = re.findall(r'\b[a-fA-F\d]{64}\b', text)
    hashes.extend(md5_hashes + sha1_hashes + sha256_hashes)

    # Find all IP addresses in the page text
    ip_addr = re.findall(r'\b((?!0)\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.((?!0)\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.((?!0)\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.((?!0)\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\b', text)
    ips = ['.'.join(match) for match in ip_addr]
    ip_addresses.extend([re.sub(r'[\[\]\(\)]', '', ips) for ips in ips])

    # Find all domain names in the page text
    domain_pattern = r'\b(?:[a-zA-Z0-9]+(?:-+[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}\b'
    scraped_domains = re.findall(domain_pattern, text)
    if url_domain:
        # Remove the domain name of the URL from the list of scraped domains
        scraped_domains = [domain for domain in scraped_domains if not domain.endswith(url_domain)]
    else:
        continue
    valid_domains = []
    for domain in scraped_domains:
        try:
            tld = get_tld('http://' + domain)
            valid_domains.append(domain)
        except:
            pass
    # Remove excluded domains
    domain_names = [domain for domain in domain_names if domain not in excluded_domains]
    # Remove duplicate domain names
    domain_names = list(dict.fromkeys(domain_names))

# Write the results to a CSV file
with open(csv_filename, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Campaign Name', 'References', 'Hashes', 'IP Addresses', 'Domains'])
    max_rows = max(len(hashes) if hashes else 0, len(ip_addresses) if ip_addresses else 0, len(domain_names if domain_names else 0))
    for i in range(max_rows):
        hash_value = hashes[i] if i < len(hashes) else ''
        ip_address = ip_addresses[i] if i < len(ip_addresses) else ''
        domain_name = domain_names[i] if i < len(domain_names) else ''
        if i == 0:
            writer.writerow([campaign_name, ', '.join(urls), hash_value, ip_address, domain_name])
        else:
            writer.writerow(['', '', hash_value, ip_address, domain_name])
