import os
import sys
import time
import shutil
from colorama import init, Fore, Style

init(autoreset=True)

# Utilities for clean screen & text centering
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def center_text(text, width=None):
    if width is None:
        width = shutil.get_terminal_size((80, 20)).columns
    return text.center(width)

def print_divider(char='─'):
    width = shutil.get_terminal_size((80, 20)).columns
    print(Fore.CYAN + char * width + Style.RESET_ALL)

def print_banner():
    clear_screen()
    banner = r"""
███╗   ██╗███████╗███████╗██╗      ██████╗ ██╗      ██████╗ ██╗   ██╗
████╗  ██║██╔════╝██╔════╝██║     ██╔═══██╗██║     ██╔═══██╗██║   ██║
██╔██╗ ██║█████╗  █████╗  ██║     ██║   ██║██║     ██║   ██║██║   ██║
██║╚██╗██║██╔══╝  ██╔══╝  ██║     ██║   ██║██║     ██║   ██║██║   ██║
██║ ╚████║███████╗███████╗███████╗╚██████╔╝███████╗╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ 
"""
    print(Fore.MAGENTA + center_text(banner))
    print(Fore.GREEN + center_text("NetSleuth - Cross-platform Network Recon Tool"))
    print(Fore.GREEN + center_text("Made for Arch Linux & Windows"))
    print(Fore.GREEN + center_text("By: Suicixde"))
    print(Fore.GREEN + center_text("Version 1.0"))
    print_divider()

def loading_spinner(duration=3, message="Processing"):
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration
    idx = 0
    while time.time() < end_time:
        sys.stdout.write(Fore.YELLOW + f"\r{message}... {spinner[idx % len(spinner)]}" + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.1)
        idx += 1
    print("\r" + " " * (len(message) + 6), end="\r")

def show_menu():
    print_divider()
    print(Fore.CYAN + center_text("Main Menu"))
    print_divider()
    options = [
        "1) Show Network Adapters",
        "2) Ping Host",
        "3) Scan Open Ports",
        "4) GeoIP Lookup",
        "5) Whois Lookup",
        "6) HTTP Headers Fetch",
        "7) DNS Records Lookup",
        "8) MAC Vendor Lookup",
        "9) Security Tips",
        "10) Export Report",
        "11) Exit"
    ]
    for opt in options:
        print(Fore.WHITE + center_text(opt))
    print_divider()

def get_choice():
    choice = input(Fore.YELLOW + "\nEnter your choice (1-11): " + Style.RESET_ALL)
    return choice.strip()

def print_network_adapters(adapters):
    print_divider()
    print(Fore.CYAN + center_text("Network Adapters Detected") + "\n")
    for adapter in adapters:
        print(Fore.GREEN + f"  - {adapter}")
    print_divider()

def print_ping_result(host, reachable):
    print_divider()
    print(Fore.CYAN + center_text(f"Ping Result for {host}"))
    print_divider()
    if reachable:
        print(Fore.GREEN + f"[+] Host {host} is reachable.")
    else:
        print(Fore.RED + f"[-] Host {host} is unreachable.")
    print_divider()

def print_ports_scan(host, ports):
    print_divider()
    print(Fore.CYAN + center_text(f"Open Ports on {host}"))
    print_divider()
    if ports:
        for port in ports:
            print(Fore.GREEN + f"  • Port {port} - OPEN")
    else:
        print(Fore.YELLOW + "No open ports found.")
    print_divider()

def print_geoip_info(ip, info):
    print_divider()
    print(Fore.CYAN + center_text(f"GeoIP Information for {ip}"))
    print_divider()
    for key, value in info.items():
        print(Fore.WHITE + f"{key}: {Fore.GREEN}{value}")
    print_divider()

def print_whois_info(domain, whois_text):
    print_divider()
    print(Fore.CYAN + center_text(f"Whois Data for {domain}"))
    print_divider()
    print(Fore.WHITE + whois_text)
    print_divider()

def print_http_headers(url, headers):
    print_divider()
    print(Fore.CYAN + center_text(f"HTTP Headers for {url}"))
    print_divider()
    for key, val in headers.items():
        print(Fore.WHITE + f"{key}: {Fore.GREEN}{val}")
    print_divider()

def print_dns_results(domain, records):
    print_divider()
    print(Fore.CYAN + center_text(f"DNS Records for {domain}"))
    print_divider()
    for record_type, values in records.items():
        print(Fore.YELLOW + f"{record_type} Records:")
        for val in values:
            print(Fore.WHITE + f"  - {val}")
    print_divider()

def print_mac_vendor(mac, vendor):
    print_divider()
    print(Fore.CYAN + center_text(f"MAC Vendor Lookup: {mac}"))
    print_divider()
    print(Fore.GREEN + f"Vendor: {vendor}")
    print_divider()

def print_security_tips(tips):
    print_divider()
    print(Fore.CYAN + center_text("Security Tips"))
    print_divider()
    for tip in tips:
        print(Fore.WHITE + f"✔ {Fore.GREEN}{tip}")
    print_divider()

def print_export_success(filename):
    print_divider()
    print(Fore.GREEN + center_text(f"Report exported successfully: {filename}"))
    print_divider()

def print_exit_message():
    print_divider()
    print(Fore.MAGENTA + center_text("Thank you for using NetSleuth! Stay safe."))
    print_divider()

def print_invalid_choice():
    print(Fore.RED + "\nInvalid choice! Please enter a number between 1 and 11.")

