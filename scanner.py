import argparse
import json
import socket
import paramiko
import yaml
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Load CVE Database (cves.json)
with open("cves.json", "r") as f:
    CVE_DB = json.load(f)

# Load weak algorithms from config/config.yaml
def load_weak_algorithms():
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)
        return {
            'ciphers': config.get('cipher', []),
            'kex': config.get('kex', []),
            'macs': config.get('mac', []),
            'host_keys': config.get('host_key', [])
        }

# Load weak algorithms (ciphers, kex, macs) from YAML file
WEAK_ALGORITHMS = load_weak_algorithms()

# Output utility
def write_output(text, output_file):
    print(text)
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{text}\n")

# Banner grabbing
def get_ssh_banner(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except Exception as e:
        write_output(f"{Fore.RED}[!] Error retrieving banner from {ip}:{port} - {str(e)}{Style.RESET_ALL}", None)
        return None

# SSH algorithm enumeration (no auth)
def enumerate_ssh_info(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)
        
        # Use the correct method to get the security options
        opts = transport.get_security_options()
        
        # Fetch the ciphers, kex, macs from security options
        ciphers = opts.ciphers if opts.ciphers else []
        kex = opts.kex if opts.kex else []
        macs = opts.macs if hasattr(opts, 'macs') and opts.macs else []

        transport.close()
        return ciphers, kex, macs
    except Exception as e:
        write_output(f"{Fore.RED}[!] Could not retrieve SSH algorithms info: {str(e)} on {ip}:{port}{Style.RESET_ALL}", None)
        return None, None, None

# Weak algorithm checks
def check_for_weak_algorithms(ciphers, kex, macs):
    weak_ciphers = [c for c in ciphers if any(w in c.lower() for w in WEAK_ALGORITHMS['ciphers'])]
    weak_kex = [k for k in kex if any(w in k.lower() for w in WEAK_ALGORITHMS['kex'])]
    weak_macs = [m for m in macs if any(w in m.lower() for w in WEAK_ALGORITHMS['macs'])]
    return weak_ciphers, weak_kex, weak_macs

# Match banner against known CVEs
def match_version(banner):
    banner = banner.lower()
    results = []
    for cve, data in CVE_DB.items():
        for version in data.get("versions", []):
            if version.lower() in banner:
                results.append((cve, data))
                break
    return results

# Security grading system
def assign_grade(cve_matches, weak_ciphers, weak_kex, weak_macs):
    score = 100

    if cve_matches:
        score -= 40
    if weak_ciphers:
        score -= 20
    if weak_kex:
        score -= 20
    if weak_macs:
        score -= 10

    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 30:
        return "D"
    else:
        return "F"

# Complete scan logic
def scan_host(ip, port, output_file=None):
    banner = get_ssh_banner(ip, port)
    if not banner:
        write_output(f"{Fore.YELLOW}[!] No SSH detected on port {port}{Style.RESET_ALL}", output_file)
        return

    write_output(f"{Fore.CYAN}[+] {ip}:{port} - Banner: {banner}{Style.RESET_ALL}", output_file)
    matches = match_version(banner)
    if matches:
        write_output(f"{Fore.RED}[!] Vulnerabilities found:{Style.RESET_ALL}", output_file)
        for cve, refs in matches:
            write_output(f"    {Fore.MAGENTA}{cve}{Style.RESET_ALL}", output_file)
            for link in refs.get("github", []):
                write_output(f"        [GitHub] {link}", output_file)
            if refs.get("exploitdb"):
                write_output(f"        [Exploit-DB] {refs['exploitdb']}", output_file)
    else:
        write_output(f"{Fore.GREEN}[-] No known CVEs matched this banner.{Style.RESET_ALL}", output_file)

    ciphers, kex, macs = enumerate_ssh_info(ip, port)
    if ciphers:
        write_output(f"{Fore.YELLOW}[+] Supported Ciphers: {ciphers}{Style.RESET_ALL}", output_file)
        write_output(f"{Fore.YELLOW}[+] Kex Algorithms: {kex}{Style.RESET_ALL}", output_file)
        write_output(f"{Fore.YELLOW}[+] MACs: {macs}{Style.RESET_ALL}", output_file)

        weak_ciphers, weak_kex, weak_macs = check_for_weak_algorithms(ciphers, kex, macs)

        if weak_ciphers or weak_kex or weak_macs:
            write_output(f"{Fore.RED}[!] Weak Algorithms Found:{Style.RESET_ALL}", output_file)
            if weak_ciphers:
                write_output(f"    Weak Ciphers: {weak_ciphers}", output_file)
            if weak_kex:
                write_output(f"    Weak KEX Algorithms: {weak_kex}", output_file)
            if weak_macs:
                write_output(f"    Weak MACs: {weak_macs}", output_file)

        grade = assign_grade(matches, weak_ciphers, weak_kex, weak_macs)
        write_output(f"{Fore.CYAN}[=] Grade: {grade}{Style.RESET_ALL}", output_file)
    else:
        write_output(f"{Fore.YELLOW}[!] Could not retrieve SSH algorithms info.{Style.RESET_ALL}", output_file)
        write_output(f"{Fore.CYAN}[=] Grade: C{Style.RESET_ALL}", output_file)

# CLI entry point
def main():
    parser = argparse.ArgumentParser(description="Ultimate SSH Vulnerability Scanner")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-l", "--list", help="File with list of IPs")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-o", "--output", help="Output file to save results")

    args = parser.parse_args()
    targets = []

    if args.ip:
        targets.append(args.ip)
    if args.list:
        with open(args.list) as f:
            targets += [line.strip() for line in f if line.strip()]

    if not targets:
        parser.print_help()
        return

    for ip in targets:
        scan_host(ip, args.port, args.output)

if __name__ == "__main__":
    main()
