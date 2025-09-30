import subprocess
import socket
import secrets
import string
import sys
import platform
import logging
import argparse
import dns.resolver
import os
import hashlib
import getpass
import json

# Configure logging
logger = logging.getLogger()
logger.handlers = []  # Remove default handlers
logging.basicConfig(filename='security_script.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_user_input(message):
    logging.info(f"User Input: {message}")

def ping_host(host):
    log_user_input(f"Pinging host: {host}")
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '4', host], universal_newlines=True, timeout=5)
        print(output)
        logging.info(f"Successfully pinged {host}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to ping {host}: {e}")
        logging.error(f"Failed to ping {host}: {e}")
    except subprocess.TimeoutExpired:
        print(f"Ping to {host} timed out.")
        logging.warning(f"Ping to {host} timed out.")

def scan_ports(host, ports):
    log_user_input(f"Scanning ports on host: {host}, ports: {ports}")
    print(f"Scanning {host} for open ports...")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    logging.info(f"Port {port} is open on {host}")
        except socket.error as e:
            print(f"Socket error: {e}")
            logging.error(f"Socket error on port {port}: {e}")
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found.")
    return open_ports

def generate_password(length=16):
    log_user_input(f"Generating password with length: {length}")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    print(f"Generated password: {password}")
    logging.info("Generated a password.")
    return password

def check_updates():
    log_user_input("Checking for updates")
    if platform.system().lower() == 'windows':
        print("Checking for Windows updates...")
        try:
            # Run the PowerShell command to get pending updates
            powershell_command = r"""
            try {
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Searcher = $Session.CreateUpdateSearcher()
                $Searcher.Online = $true
                $SearchResult = $Searcher.Search("IsInstalled=0 and Type='Software'")

                $Updates = @()
                for ($i = 0; $i -lt $SearchResult.Updates.Count; $i++) {
                    $Update = $SearchResult.Updates.Item($i)
                    $Updates += [PSCustomObject]@{
                        Title       = $Update.Title
                        Description = $Update.Description
                        KBArticleIDs = $Update.KBArticleIDs -join ", "
                    }
                }
            
                # Convert the output to JSON for easy parsing
                if ($Updates) {
                    $json = $Updates | ConvertTo-Json
                    Write-Output $json
                } else {
                    Write-Output "[]"
                }
                
            }
            catch {
                Write-Output "[]"
            }
            """
            result = subprocess.run(['powershell', '-Command', powershell_command], capture_output=True, text=True, check=False)
            #testing
            if result.returncode == 0:
                updates_json = result.stdout.strip()
                try:
                    updates = json.loads(updates_json)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}. JSON String: {updates_json}")
                    logging.error(f"Error decoding JSON: {e}. JSON String: {updates_json}")
                    return
                
                if updates:
                    print("Pending Windows Updates:")
                    for update in updates:
                        print(f"  Title: {update['Title']}")
                        print(f"  Description: {update['Description']}")
                        print(f"  KB Article IDs: {update['KBArticleIDs']}")
                        print("-" * 30)
                    logging.info("Pending Windows updates found.")
                else:
                    print("No pending Windows updates found.")
                    logging.info("No pending Windows updates found.")
            else:
                print("Error checking updates:", result.stderr)
                logging.error(f"Error checking updates: {result.stderr}")
        except Exception as e:
            print("Error checking updates:", e)
            logging.error(f"Error checking updates: {e}")
    else:
        print("Update check is only implemented for Windows.")
        logging.warning("Update check is only implemented for Windows.")

def check_firewall_rules():
    log_user_input("Checking firewall rules")
    print("Checking Firewall Rules...")
    if platform.system().lower() == 'windows':
        try:
            output = subprocess.check_output(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], universal_newlines=True)
            print(output)
            logging.info("Firewall rules checked.")
        except Exception as e:
            print("Error checking firewall rules:", e)
            logging.error(f"Error checking firewall rules: {e}")
    else:
        try:
            output = subprocess.check_output(['sudo', 'iptables', '-L'], universal_newlines=True)
            print(output)
            logging.info("Firewall rules checked.")
        except Exception as e:
            print("Error checking firewall rules (iptables):", e)
            logging.error(f"Error checking firewall rules (iptables): {e}")

def perform_dns_lookup(domain):
    log_user_input(f"Performing DNS lookup for domain: {domain}")
    print(f"Performing DNS lookup for {domain}...")
    try:
        resolver = dns.resolver.Resolver()
        a_records = resolver.resolve(domain, 'A')
        print("\nA Records:")
        for record in a_records:
            print(record)
            logging.info(f"A Record: {record}")
        mx_records = resolver.resolve(domain, 'MX')
        print("\nMX Records:")
        for record in mx_records:
            print(record)
            logging.info(f"MX Record: {record}")
        ns_records = resolver.resolve(domain, 'NS')
        print("\nNS Records:")
        for record in ns_records:
            print(record)
            logging.info(f"NS Record: {record}")
    except Exception as e:
        print("Error performing DNS lookup:", e)
        logging.error(f"Error performing DNS lookup for {domain}: {e}")

def file_integrity_check(filepath, expected_hash=None):
    log_user_input(f"Performing file integrity check on: {filepath}")
    print(f"Checking integrity of {filepath}...")
    try:
        # Use a more memory-efficient approach for large files
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(4096)  # Read in 4KB chunks
                if not chunk:
                    break
                sha256_hash.update(chunk)
        hex_dig = sha256_hash.hexdigest()
        print(f"SHA256 Hash: {hex_dig}")
        logging.info(f"File integrity check SHA256 hash: {hex_dig} for {filepath}")

        if expected_hash:
            if hex_dig.lower() == expected_hash.lower():
                print("Hash verification successful: The file is intact.")
                logging.info("Hash verification successful: The file is intact.")
            else:
                print("Hash verification failed: The file may be corrupted or modified.")
                logging.warning("Hash verification failed: The file may be corrupted or modified.")
        else:
            print("No expected hash provided for comparison.")
            logging.info("No expected hash provided for comparison.")

    except Exception as e:
        print(f"Error calculating hash: {e}")
        logging.error(f"Error calculating hash for {filepath}: {e}")

def monitor_user_accounts():
    log_user_input("Monitoring user accounts")
    print("Monitoring User Accounts...")
    try:
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['powershell', '-Command', 'Get-LocalUser | Select-Object Name, Enabled'], universal_newlines=True)
            print(output)
            logging.info("User account monitoring performed.")
        else:
            output = subprocess.check_output(['getent', 'passwd'], universal_newlines=True)
            print("User accounts:\n", output)
            logging.info("User account monitoring performed.")

    except Exception as e:
        print("Error monitoring user accounts:", e)
        logging.error(f"Error monitoring user accounts: {e}")

def main():
    parser = argparse.ArgumentParser(description="Security Script Menu")
    parser.add_argument("-p", "--ping", help="Ping a host")
    parser.add_argument("-s", "--scan", help="Scan ports on a host", nargs='+', type=int)
    parser.add_argument("-g", "--generate", help="Generate a password", type=int)
    parser.add_argument("-u", "--updates", action="store_true", help="Check for updates")
    parser.add_argument("-f", "--firewall", action="store_true", help="Check firewall rules")
    parser.add_argument("-d", "--dns", help="Perform DNS lookup")
    parser.add_argument("-i", "--integrity", help="File integrity check", nargs='?', const=True)
    parser.add_argument("--hash", help="Expected SHA256 hash for file integrity check")
    parser.add_argument("-a", "--accounts", action="store_true", help="Monitor user accounts")

    args = parser.parse_args()

    if args.ping:
        ping_host(args.ping)
    if args.scan:
        host = input("Enter host to scan: ")
        log_user_input(f"User entered host to scan: {host}")
        scan_ports(host, args.scan)
    if args.generate:
        generate_password(args.generate)
    if args.updates:
        check_updates()
    if args.firewall:
        check_firewall_rules()
    if args.dns:
        perform_dns_lookup(args.dns)
    if args.integrity:
        filepath = input("Enter filepath to check integrity: ")
        log_user_input(f"User entered filepath for integrity check: {filepath}")
        file_integrity_check(filepath, args.hash)
    if args.accounts:
        monitor_user_accounts()

    if not any(vars(args).values()):
        while True:
            print("\nSecurity Script Menu:")
            print("1. Ping a host")
            print("2. Scan for open ports")
            print("3. Generate secure password")
            print("4. Check for available updates (Windows)")
            print("5. Check firewall rules")
            print("6. Perform DNS lookup")
            print("7. File integrity check")
            print("8. Monitor user accounts")
            print("9. Exit")
            choice = input("Select an option: ")
            log_user_input(f"User selected menu option: {choice}")

            if choice == '1':
                host = input("Enter host to ping: ")
                log_user_input(f"User entered host to ping: {host}")
                ping_host(host)
            elif choice == '2':
                host = input("Enter host to scan: ")
                log_user_input(f"User entered host to scan: {host}")
                ports = input("Enter comma-separated ports (e.g., 22,80,443): ")
                log_user_input(f"User entered host to scan: {ports}")
                try:
                    ports = [int(p.strip()) for p in ports.split(',')]
                except ValueError:
                    print("Invalid port format. Please use comma-separated integers.")
                    continue
                scan_ports(host, ports)
            elif choice == '3':
                length = input("Enter password length (default 16): ")
                log_user_input(f"User entered password length: {length}")
                length = int(length) if length.isdigit() else 16
                generate_password(length)
            elif choice == '4':
                check_updates()
            elif choice == '5':
                check_firewall_rules()
            elif choice == '6':
                domain = input("Enter domain to perform DNS lookup: ")
                log_user_input(f"User entered domain for DNS lookup: {domain}")
                perform_dns_lookup(domain)
            elif choice == '7':
                filepath = input("Enter filepath to check integrity: ")
                log_user_input(f"User entered filepath for integrity check: {filepath}")
                expected_hash = input("Enter expected SHA256 hash (optional): ")
                log_user_input(f"User entered expected hash: {expected_hash}")
                file_integrity_check(filepath, expected_hash)
            elif choice == '8':
                monitor_user_accounts()
            elif choice == '9':
                print("Exiting.")
                break
            else:
                print("Invalid option.")

if __name__ == "__main__":
    main()