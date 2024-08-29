import socket
import dns.resolver
from urllib.parse import urlparse
import subprocess
from tqdm import tqdm
import re

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
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
            ip = socket.gethostbyname(host)
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, 80))
            sock.send(request.encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            return response.decode(errors='ignore')
        except Exception as e:
            print(f"Error making request to {url}: {e}")
            return ""

    def parse_response(self, response):
        # Improved subdomain extraction using regular expressions
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
    """Retrieve IP addresses associated with a domain name."""
    try:
        result = dns.resolver.resolve(domain_name, 'A')
        return [ip.address for ip in result]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
        return f"{BRIGHT_RED}DNS resolution error: {str(e)}{RESET}"
    except Exception as e:
        return f"{BRIGHT_RED}{str(e)}{RESET}"


def reverse_dns(ip_address):
    """Perform reverse DNS lookup to get domain name from IP address."""
    try:
        domain_name, _, _ = socket.gethostbyaddr(ip_address)
        return domain_name
    except (socket.herror, socket.gaierror) as e:
        return f"{BRIGHT_RED}Failed to resolve {ip_address}: {e}{RESET}"
    except Exception as e:
        return f"{BRIGHT_RED}Error resolving {ip_address}: {e}{RESET}"


def extract_domain_name(url):
    """Extract domain name from URL."""
    try:
        parsed_url = urlparse(url)
        domain_name = parsed_url.hostname
        if not domain_name:
            raise ValueError("Invalid URL")
        return domain_name
    except Exception as e:
        return f"{BRIGHT_RED}Error parsing URL: {str(e)}{RESET}"


def check_unauthorized_access(domain_name, domain_names):
    """Check for unauthorized access vulnerabilities."""
    try:
        if domain_names:
            print(f"{BRIGHT_CYAN}\nReverse DNS results associated with IP addresses:{RESET}")
            for name in domain_names:
                print(name)

            s3_present = any('s3' in name for name in domain_names)
            if s3_present:
                command = f"aws s3 ls s3://{domain_name} --no-sign-request"
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    print(
                        f"{BRIGHT_RED}Warning: AWS CLI command failed for unauthorized access with error: {result.stderr}{RESET}")
                else:
                    print(f"{BRIGHT_GREEN}Results accessible without authentication:\n{RESET}")
                    print(result.stdout)  # Print the command output
            else:
                print(f"{BRIGHT_BLUE}No domain names contain 's3'.{RESET}")
    except Exception as e:
        print(f"{BRIGHT_RED}Error in checking unauthorized access: {e}{RESET}")


def check_authorized_access(domain_name, domain_names):
    """Check for authorized access vulnerabilities. Here the profile should have s3bucketaccess in aws"""
    try:
        if domain_names:
            print(f"{BRIGHT_CYAN}\nDomain names associated with IP addresses:\n{RESET}")
            for name in domain_names:
                print(name)

            s3_present = any('s3' in name or 'aws' in name for name in domain_names)
            profile_name = input(f"{BRIGHT_CYAN}enter the profile name that has given s3fullbucket access : ")
            if s3_present:
                command = f"aws s3 ls s3://{domain_name} --profile {profile_name}"
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"{BRIGHT_RED}\nDue to the authorization permissions assigned to you, access to "
                          f"the S3 bucket is not permitted.\nReason: {result.stderr}{RESET}")
                else:
                    print(f"{BRIGHT_GREEN}S3 bucket is accessible with the specified profile.\n{RESET}")
                    print(result.stdout)  # Print the command output
            else:
                print(f"{BRIGHT_BLUE}No domain names contain 's3'.{RESET}")
    except Exception as e:
        print(f"{BRIGHT_RED}Error in checking authorized access: {e}{RESET}")


def main():
    # Get URL input from the user
    url = input(f"{BRIGHT_BLUE}\nEnter the URL: {RESET}")

    # Extract the domain name from the URL
    main_domain_name = extract_domain_name(url)
    if isinstance(main_domain_name, str) and "Error" in main_domain_name:
        print(main_domain_name)
        return

    # Enumerate subdomains
    print(f"{BRIGHT_CYAN}Enumerating subdomains for {main_domain_name}...{RESET}")
    enumerator = SubdomainEnumerator(main_domain_name)
    enumerator.run()
    all_domains = enumerator.subdomains.union({main_domain_name})

    with tqdm(total=len(all_domains), desc=f"{BRIGHT_CYAN}Processing domains{RESET}", unit="domain", ncols=100) as pbar:
        for domain in all_domains:
            print(f"{BRIGHT_BLUE}\nProcessing domain: {domain}{RESET}")

            # Find IP addresses associated with the domain name
            ips = get_ip_addresses(domain)
            print(f"{BRIGHT_GREEN}The IP addresses of {domain} are {ips}{RESET}")

            if isinstance(ips, list):
                # Collect unique domain names through reverse DNS lookup
                domain_names = set()
                for ip in ips:
                    reverse_dns_name = reverse_dns(ip)
                    if isinstance(reverse_dns_name, str) and reverse_dns_name:
                        domain_names.add(reverse_dns_name)

                # Handle reverse DNS results and check for vulnerabilities
                check_unauthorized_access(domain, domain_names)
                check_authorized_access(domain, domain_names)
            else:
                print(f"{BRIGHT_RED}DNS resolution error: {ips}{RESET}")

            pbar.update(1)


if __name__ == "__main__":
    main()
