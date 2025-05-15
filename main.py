# main.py
import subprocess
import platform
import socket
import sys
import os
import json
import time
from datetime import datetime
import common

import requests
import whois
import dns.resolver

from common import (
    clear_screen, print_banner, show_menu, get_choice,
    print_network_adapters, print_ping_result, print_ports_scan,
    print_geoip_info, print_whois_info, print_http_headers,
    print_dns_results, print_mac_vendor, print_security_tips,
    print_invalid_choice, print_exit_message, print_export_success,
    loading_spinner,
)

# Global to store last scan report for exporting
last_report = {
    "network_adapters": [],
    "ping": {},
    "open_ports": [],
    "geoip": {},
    "whois": "",
    "http_headers": {},
    "dns": {},
    "mac_vendor": "",
    "security_tips": [
        "Use strong, unique passwords for all accounts.",
        "Enable two-factor authentication wherever possible.",
        "Keep your software and OS updated.",
        "Be cautious of suspicious emails and links.",
        "Use a firewall and antivirus software."
    ]
}

# Helper: Get network adapters (cross platform)
def get_network_adapters():
    adapters = []
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output("ipconfig", encoding='utf-8')
            for line in output.splitlines():
                if "IPv4 Address" in line or "IPv4-adresse" in line:
                    adapters.append(line.strip())
        else:  # Linux/macOS
            output = subprocess.check_output("ip -o -4 addr show", shell=True, encoding='utf-8')
            for line in output.splitlines():
                parts = line.split()
                if len(parts) > 3:
                    iface = parts[1]
                    ip = parts[3].split('/')[0]
                    adapters.append(f"{iface}: {ip}")
    except Exception as e:
        adapters.append(f"Error getting adapters: {e}")
    return adapters

# Helper: Ping host (simple)
def ping_host(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        completed = subprocess.run(['ping', param, '1', host], stdout=subprocess.DEVNULL)
        return completed.returncode == 0
    except Exception:
        return False

# Helper: Scan common ports on localhost (can be extended)
def scan_common_ports(host='127.0.0.1'):
    common_ports = [22, 80, 443, 53, 8080, 3306]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Helper: GeoIP lookup using free API (ip-api.com)
def geoip_lookup(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,query")
        data = resp.json()
        if data.get('status') == 'success':
            return {
                "IP": data.get('query'),
                "Country": data.get('country'),
                "Region": data.get('regionName'),
                "City": data.get('city'),
                "ISP": data.get('isp')
            }
        else:
            return {"Error": "Lookup failed or invalid IP"}
    except Exception as e:
        return {"Error": str(e)}

# Helper: Whois lookup
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w, dict):
            return json.dumps(w, indent=2, default=str)
        else:
            return str(w)
    except Exception as e:
        return f"Whois lookup failed: {e}"

# Helper: Fetch HTTP headers
def fetch_http_headers(url):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        resp = requests.head(url, timeout=5)
        return dict(resp.headers)
    except Exception as e:
        return {"Error": str(e)}

# Helper: DNS lookup (A, MX, TXT)
def dns_lookup(domain):
    records = {}
    try:
        resolver = dns.resolver.Resolver()
        records['A'] = [str(r) for r in resolver.resolve(domain, 'A')]
    except Exception:
        records['A'] = []
    try:
        records['MX'] = [str(r.exchange) for r in resolver.resolve(domain, 'MX')]
    except Exception:
        records['MX'] = []
    try:
        records['TXT'] = [str(r) for r in resolver.resolve(domain, 'TXT')]
    except Exception:
        records['TXT'] = []
    return records

# Helper: MAC vendor lookup (basic)
def mac_vendor_lookup(mac):
    # Basic OUI prefixes sample (extendable)
    oui_map = {
        "00:1A:2B": "SampleVendor Inc.",
        "00:1B:63": "AnotherVendor Ltd.",
        "AC:DE:48": "Wi-Fi Alliance",
        # Add more as needed
    }
    mac_prefix = mac.upper()[0:8]
    return oui_map.get(mac_prefix, "Unknown Vendor")

# Export last report
def export_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"netsentry_report_{timestamp}.txt"
    try:
        with open(filename, "w") as f:
            f.write("NetSentry Scan Report\n")
            f.write(f"Generated on: {datetime.now()}\n\n")

            f.write("Network Adapters:\n")
            for adapter in last_report["network_adapters"]:
                f.write(f"  - {adapter}\n")

            f.write("\nPing Results:\n")
            for host, reachable in last_report["ping"].items():
                status = "Reachable" if reachable else "Unreachable"
                f.write(f"  {host}: {status}\n")

            f.write("\nOpen Ports on localhost:\n")
            for port in last_report["open_ports"]:
                f.write(f"  Port {port} is OPEN\n")

            f.write("\nGeoIP Lookup:\n")
            for k, v in last_report["geoip"].items():
                f.write(f"  {k}: {v}\n")

            f.write("\nWhois Info:\n")
            f.write(last_report["whois"] + "\n")

            f.write("\nHTTP Headers:\n")
            for k, v in last_report["http_headers"].items():
                f.write(f"  {k}: {v}\n")

            f.write("\nDNS Records:\n")
            for record_type, vals in last_report["dns"].items():
                f.write(f"  {record_type}:\n")
                for val in vals:
                    f.write(f"    - {val}\n")

            f.write(f"\nMAC Vendor: {last_report['mac_vendor']}\n")

            f.write("\nSecurity Tips:\n")
            for tip in last_report["security_tips"]:
                f.write(f"  - {tip}\n")
        return filename
    except Exception as e:
        print(f"Error exporting report: {e}")
        return None


def main():
    common.clear_screen()
    common.print_banner()

    while True:
        common.show_menu()
        choice = common.get_choice()

        if choice == '1':
            # Example: Show network adapters (dummy list)
            adapters = ['eth0 - 192.168.1.10', 'wlan0 - 192.168.1.15']
            common.print_network_adapters(adapters)
            input("\nPress Enter to continue...")

        elif choice == '2':
            # Example: Ping host
            host = input("Enter host to ping: ")
            common.loading_spinner(2, "Pinging")
            reachable = True  # simulate ping success
            common.print_ping_result(host, reachable)
            input("\nPress Enter to continue...")

        elif choice == '3':
            # Scan ports example
            host = "localhost"
            common.loading_spinner(2, "Scanning Ports")
            open_ports = [22, 80, 443]
            common.print_ports_scan(host, open_ports)
            input("\nPress Enter to continue...")

        elif choice == '4':
            # GeoIP example
            ip = "8.8.8.8"
            common.loading_spinner(2, "Looking up GeoIP")
            info = {
                "Country": "United States",
                "Region": "California",
                "City": "Mountain View",
                "ISP": "Google LLC"
            }
            common.print_geoip_info(ip, info)
            input("\nPress Enter to continue...")

        elif choice == '5':
            # Whois example
            domain = "example.com"
            common.loading_spinner(2, "Fetching Whois")
            whois_info = "Domain Name: example.com\nRegistrar: Example Registrar\nCreation Date: 1995-08-13"
            common.print_whois_info(domain, whois_info)
            input("\nPress Enter to continue...")

        elif choice == '6':
            # HTTP headers example
            url = "https://example.com"
            common.loading_spinner(2, "Fetching HTTP Headers")
            headers = {
                "Content-Type": "text/html; charset=UTF-8",
                "Server": "Apache",
                "Cache-Control": "max-age=3600"
            }
            common.print_http_headers(url, headers)
            input("\nPress Enter to continue...")

        elif choice == '7':
            # DNS lookup example
            domain = "example.com"
            common.loading_spinner(2, "Performing DNS Lookup")
            records = {
                "A": ["93.184.216.34"],
                "MX": ["mail.example.com"],
                "TXT": ["v=spf1 include:_spf.example.com ~all"]
            }
            common.print_dns_results(domain, records)
            input("\nPress Enter to continue...")

        elif choice == '8':
            # MAC vendor lookup example
            mac = "00:1A:2B:3C:4D:5E"
            vendor = "ExampleCorp Inc."
            common.loading_spinner(1.5, "Looking up MAC Vendor")
            common.print_mac_vendor(mac, vendor)
            input("\nPress Enter to continue...")

        elif choice == '9':
            # Security tips example
            tips = [
                "Use strong, unique passwords.",
                "Keep your software updated.",
                "Enable two-factor authentication.",
                "Regularly backup your data."
            ]
            common.print_security_tips(tips)
            input("\nPress Enter to continue...")

        elif choice == '10':
            # Export report example
            filename = "netsentry_report.txt"
            # (Simulate export)
            common.loading_spinner(2, "Exporting Report")
            common.print_export_success(filename)
            input("\nPress Enter to continue...")

        elif choice == '11':
            common.print_exit_message()
            break

        else:
            common.print_invalid_choice()
            time.sleep(1)

if __name__ == "__main__":
    main()