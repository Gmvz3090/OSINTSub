import requests
import json

VIRUSTOTAL_API_KEY = "PASTE_VIRUSTOTAL_KEY_HERE"
SECURITYTRAILS_API_KEY = "PASTE_SECURITYTRAILS_KEY_HERE"

def normalize_subdomain(subdomain):
    return subdomain.strip().rstrip('.').lower()

def query_crtsh(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = normalize_subdomain(entry['name_value'])
                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)
    except Exception:
        pass
    return subdomains

def query_virustotal(domain):
    subdomains = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data.get('data', []):
                subdomain = normalize_subdomain(entry['id'])
                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)
    except Exception:
        pass
    return subdomains

def query_securitytrails(domain):
    subdomains = set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data.get('subdomains', []):
                subdomain = normalize_subdomain(f"{entry}.{domain}")
                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)
    except Exception:
        pass
    return subdomains

def main(domain):
    print(f"[*] Gathering subdomains for {domain} using OSINT...")

    subdomains = set()
    subdomains.update(query_crtsh(domain))
    subdomains.update(query_virustotal(domain))
    subdomains.update(query_securitytrails(domain))
    final_subdomains = set()
    for item in subdomains:
        if "\n" in item:
            for sub in item.split('\n'):
                final_subdomains.add(sub.strip().rstrip('.').lower())
        else:
            final_subdomains.add(item.strip().rstrip('.').lower())

    final_subdomains.discard(domain)
    final_subdomains.discard('')

    print(f"\n[+] Found {len(final_subdomains)} truly unique subdomains:")
    for sub in sorted(final_subdomains):
        print(sub)

if __name__ == "__main__":
    DOMAIN = input('Target: ')
    main(DOMAIN)
