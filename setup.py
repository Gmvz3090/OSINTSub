import re

def configure_keys():
    print("[-] Configuring API keys for sub.py")
    
    vt_key = input("Enter VirusTotal API Key: ").strip()
    st_key = input("Enter SecurityTrails API Key: ").strip()

    with open("sub.py", "r") as f:
        content = f.read()

    updated = re.sub(
        r'VIRUSTOTAL_API_KEY = "PASTE_VIRUSTOTAL_KEY_HERE"',
        f'VIRUSTOTAL_API_KEY = "{vt_key}"',
        content
    )
    
    updated = re.sub(
        r'SECURITYTRAILS_API_KEY = "PASTE_SECURITYTRAILS_KEY_HERE"',
        f'SECURITYTRAILS_API_KEY = "{st_key}"',
        updated
    )

    with open("sub.py", "w") as f:
        f.write(updated)
    
    print("[+] Configuration complete! You can now use sub.py")

if __name__ == "__main__":
    configure_keys()
