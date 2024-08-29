import dns.resolver
from urllib.parse import urlparse
from tqdm import tqdm
from google.cloud import storage
from google.auth.exceptions import DefaultCredentialsError
import requests
import re
import socket

# Color codes
BRIGHT_RED = "\033[91m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_BLUE = "\033[94m"
RESET = "\033[0m"

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.search_engines = [
            f"https://www.google.com/search?q=site:{domain}",
            f"https://search.yahoo.com/search?p=site:{domain}",
            f"https://www.bing.com/search?q=site:{domain}"
        ]

    def make_request(self, url):
        try:
            response = requests.get(url, timeout=10)
            return response.text
        except requests.RequestException as e:
            print(f"Error making request to {url}: {e}")
            return ""

    def parse_response(self, response):
        subdomain_regex = r'([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.' + re.escape(self.domain) + r')'
        found_subdomains = re.findall(subdomain_regex, response)
        for subdomain in found_subdomains:
            if subdomain.endswith(self.domain) and subdomain != self.domain:
                self.subdomains.add(subdomain)

    def enumerate_subdomains(self):
        for engine in self.search_engines:
            print(f"Searching in {engine}")
            response = self.make_request(engine)
            if response:
                self.parse_response(response)

    def run(self):
        self.enumerate_subdomains()
        if self.subdomains:
            print("\n[+] Discovered subdomains:")
            for subdomain in sorted(self.subdomains):
                print(subdomain)
        else:
            print("[-] No subdomains found.")

def get_ip_addresses(domain_name):
    try:
        result = dns.resolver.resolve(domain_name, 'A')
        return [ip.address for ip in result]
    except dns.resolver.NXDOMAIN:
        return f"{BRIGHT_RED}DNS resolution error: Domain {domain_name} does not exist.{RESET}"
    except dns.resolver.Timeout:
        return f"{BRIGHT_RED}DNS resolution error: Timeout while resolving {domain_name}.{RESET}"
    except Exception as e:
        return f"{BRIGHT_RED}DNS resolution error: {str(e)}{RESET}"

def extract_domain_name(url):
    try:
        parsed_url = urlparse(url)
        domain_name = parsed_url.hostname
        if not domain_name:
            raise ValueError("Invalid URL")
        return domain_name
    except Exception as e:
        return f"{BRIGHT_RED}Error parsing URL: {str(e)}{RESET}"

def check_google_cloud_storage(storage_client, domain_name):
    try:
        bucket = storage_client.bucket(domain_name)
        if bucket.exists():
            print(f"{BRIGHT_GREEN}Bucket {domain_name} exists and is accessible.{RESET}")
        else:
            print(f"{BRIGHT_RED}Bucket {domain_name} is not accessible or it does not exist. \n{RESET}")
    except Exception as e:
        print(f"{BRIGHT_RED}Error in checking Google Cloud Storage access: {e}{RESET}")

def main():
    url = input(f"{BRIGHT_BLUE}\nEnter the URL: {RESET}")

    main_domain_name = extract_domain_name(url)
    if isinstance(main_domain_name, str) and "Error" in main_domain_name:
        print(main_domain_name)
        return

    enumerator = SubdomainEnumerator(main_domain_name)
    enumerator.run()
    subdomains = enumerator.subdomains

    all_domains = set(subdomains) | {main_domain_name}
    print(f"{BRIGHT_GREEN}\nDomains to process: {all_domains}{RESET}")

    key_file = input("Enter the path to the Google Cloud key file JSON: ")

    try:
        storage_client = storage.Client.from_service_account_json(key_file)
    except DefaultCredentialsError:
        print(f"{BRIGHT_RED}Error: Invalid or missing Google Cloud credentials.{RESET}")
        return
    except Exception as e:
        print(f"{BRIGHT_RED}Error initializing Google Cloud Storage client: {e}{RESET}")
        return

    with tqdm(total=len(all_domains), desc=f"{BRIGHT_CYAN}Processing domains{RESET}", unit="domain", ncols=100) as pbar:
        for domain in all_domains:
            print(f"{BRIGHT_BLUE}\nProcessing domain: {domain}{RESET}")
            check_google_cloud_storage(storage_client, domain)
            pbar.update(1)

if __name__ == "__main__":
    main()
