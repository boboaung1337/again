#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "impacket",
# ]
# ///

# FixTime
# Author: x4c1s
# Date: 16/11/25
# License: WTFPL
# Improved by muzaffar1337 & Gemini (Fixed concurrent warning handling)

import requests
import subprocess
import argparse
import socket
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures
import threading
import sys
import warnings

# --- Corrected Imports for Warning Handling ---
try:
    # Required for SMB functionality
    from impacket.smbconnection import SMBConnection
except ImportError:
    print("[-] Required module 'impacket' not found. Install with: pip install impacket")
    sys.exit(1)

try:
    # Correct path for InsecureRequestWarning used by requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    # Fallback for older versions of requests/urllib3
    warnings.warn("Could not import InsecureRequestWarning from urllib3. Warning suppression may fail.", RuntimeWarning)
    # Define a dummy class to prevent the script from crashing immediately if the required class can't be imported
    class InsecureRequestWarning(Warning):
        pass

# Configuration
TIMEOUT = 3 # Timeout for socket and HTTP requests in seconds
MAX_WORKERS = 3 # Number of concurrent threads for time retrieval

# Lock for printing output
print_lock = threading.Lock()

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Sync local time with remote Windows target")
parser.add_argument("-u", "--url", help="Target URL/IP")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
parser.add_argument("--restore-ntp", action="store_true", help="Re-enable NTP and exit")
args = parser.parse_args()

# --- Helper Functions ---

def log(msg, force=False):
    """Prints a message if verbose mode is on, or if forced."""
    if args.verbose or force:
        with print_lock:
            print(msg)

def restore_ntp():
    """Re-enables the Network Time Protocol (NTP) service."""
    try:
        print("[*] Re-enabling NTP")
        # Ensure we use 'sudo' for timedatectl
        subprocess.run(["sudo", "timedatectl", "set-ntp", "on"], check=True, capture_output=True)
        print("[+] NTP restored successfully")
    except Exception as e:
        print(f"[-] Failed to restore NTP. Run with sudo or check system configuration. Error: {e}")

def validate_url():
    """Parses and normalizes the target URL."""
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Use 'netloc' or 'hostname' for extraction
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path.split(':')[0]
    
    return url, hostname

def check_port(host, port):
    """Quickly checks if a specific TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        log(f"[-] Port check for {host}:{port} failed: {e}")
        return False

# --- Time Retrieval Functions (Concurrent Tasks) ---

def get_time_winrm(url, host):
    """Attempts to retrieve time via WinRM (Port 5985) using the Date header."""
    port = 5985
    try:
        if not check_port(host, port):
            log(f"[-] Port {port} (WinRM) closed or unresponsive.")
            return None
        
        log(f"[*] Trying WinRM ({port})")
        
        # Use a HEAD request to minimize data transfer
        # Suppress InsecureRequestWarning correctly using the imported class
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            r = requests.head(f"{url}:{port}/wsman", timeout=TIMEOUT, verify=False)
        
        if 'Date' in r.headers:
            date_str = r.headers['Date']
            # Example: 'Sat, 06 Dec 2025 10:48:04 GMT'
            remote_time = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %Z')
            return remote_time.strftime('%Y-%m-%d %H:%M:%S'), "WinRM"
        log("[-] WinRM header missing 'Date'.")
    except requests.exceptions.RequestException as e:
        log(f"[-] WinRM failed: {type(e).__name__} - {e}")
    except ValueError as e:
        log(f"[-] WinRM time parsing error: {e}")
    return None

def get_time_smb(host):
    """Attempts to retrieve time via SMB (Port 445)."""
    port = 445
    try:
        if not check_port(host, port):
            log(f"[-] Port {port} (SMB) closed or unresponsive.")
            return None
            
        log(f"[*] Trying SMB ({port})")
        # Anonymous login is sufficient for time retrieval
        conn = SMBConnection(host, host, sess_port=port, timeout=TIMEOUT)
        
        # getSMBServer().get_server_time() provides a highly accurate remote time
        server_time = conn.getSMBServer().get_server_time()
        conn.close()
        return server_time.strftime('%Y-%m-%d %H:%M:%S'), "SMB"
    except Exception as e:
        # impacket exceptions are caught here
        log(f"[-] SMB failed: {type(e).__name__} - {e}")
    return None

def get_remote_time_concurrent(url, host):
    """
    Attempts to retrieve time concurrently using multiple protocols.
    Stops and returns the first successful result.
    """
    # Functions and their arguments to be executed concurrently
    tasks = [
        (get_time_winrm, (url, host)),
        (get_time_smb, (host,)),
    ]
    
    found_time = None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_method = {
            executor.submit(func, *args): func.__name__ 
            for func, args in tasks
        }
        
        # Iterate over results as they complete
        for future in concurrent.futures.as_completed(future_to_method):
            result = future.result()
            if result:
                found_time = result 
                # Found the time, stop all other threads
                executor.shutdown(wait=False, cancel_futures=True)
                break
    
    if found_time:
        return found_time
    else:
        return None, None

def sync_time(time_str):
    """Sets the local system time using the retrieved time (in UTC)."""
    try:
        print("[*] Disabling NTP...")
        # 1. Disable NTP to allow manual time setting
        subprocess.run(["sudo", "timedatectl", "set-ntp", "off"], check=True, capture_output=True)
        
        print(f"[*] Setting time to {time_str} (UTC)...")
        # 2. Set the time string, using -u to treat it as UTC
        subprocess.run(["sudo", "date", "-u", "-s", time_str], check=True, capture_output=True)
        
        print("[+] Time synced successfully!")
        print("[*] Local time is now set to the remote server's time.")
        print("[*] IMPORTANT: Run with **--restore-ntp** when finished to re-enable automatic sync.")
        
    except Exception as e:
        print(f"[-] Failed to sync time. Ensure the script is run with '**sudo**'. Error: {e}")

# --- Main Execution ---

def main():
    """Main execution function."""
    if args.restore_ntp:
        restore_ntp()
        return
    
    if not args.url:
        parser.error("-u/--url is required unless using --restore-ntp")
    
    # 1. Validate and extract host
    url, host = validate_url()
    
    print(f"[*] Target: {host}")
    
    # 2. Concurrently try to get remote time
    time, method = get_remote_time_concurrent(url, host)
    
    # 3. Process the result
    if time:
        print(f"\n[+] Remote Time Retrieved via **{method}**: **{time}**")
        sync_time(time)
    else:
        print("\n[-] Failed to fetch remote time. No accessible services (5985, 445) found or connection timed out.")

if __name__ == "__main__":
    # Suppress InsecureRequestWarning globally for simplicity and to avoid repetitive warnings.
    # We use the correctly imported InsecureRequestWarning class.
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning) 
    
    main()