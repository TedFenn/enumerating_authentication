#!/usr/bin/env python3

"""
enum_hosts_smb_winrm_rdp.py

Usage example:
--------------
python3 enum_hosts_smb_winrm_rdp.py \
  -i 192.168.124.245-249 192.168.124.191 192.168.124.189 \
  -u user \
  -p 'password' \
  -d domain.com \
  --smb --winrm --rdp \
  --threads 8
"""

import subprocess
import datetime
import argparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Config
MAX_THREADS = 10
log_lock = Lock()
successes = []

# -------------------------------
# Helpers
# -------------------------------
def run_cmd(cmd):
    log(f"[>] Executing: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=30)
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def log(line):
    with log_lock:
        with open(outfile, "a") as f:
            f.write(line + "\n")
        print(line)

def expand_ips(ip_input_list):
    result = []
    for item in ip_input_list:
        if re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", item):
            base = ".".join(item.split(".")[:3])
            start = int(item.split(".")[3].split("-")[0])
            end = int(item.split("-")[1])
            for i in range(start, end + 1):
                result.append(f"{base}.{i}")
        else:
            result.append(item)
    return result

def parse_success(output, ip, proto):
    for line in output.splitlines():
        if proto in line and ip in line and "[+]" in line:
            return line
    return None

# -------------------------------
# Main per-host worker
# -------------------------------
def enumerate_host(ip, args):
    log(f"\n--- Enumerating {ip} ---")

    if args.smb:
        smb_cmd = f"crackmapexec smb {ip} -u {args.username} -p '{args.password}' -d {args.domain} --continue-on-success"
        smb_out = run_cmd(smb_cmd)
        success_line = parse_success(smb_out, ip, "SMB")
        if success_line:
            log(f"[+] SMB SUCCESS: {ip}")
            log(f"    RAW: {success_line}")
            pwned = "Pwn3d!" in smb_out
            successes.append(["SMB", ip, "445", args.username, "YES", "YES" if pwned else "NO"])
        else:
            log(f"[-] SMB FAILED: {ip}")
            log(f"    OUTPUT:\n{smb_out}")

    if args.winrm:
        winrm_cmd = f"crackmapexec winrm {ip} -u {args.username} -p '{args.password}' -d {args.domain} --continue-on-success"
        winrm_out = run_cmd(winrm_cmd)
        success_line = parse_success(winrm_out, ip, "WINRM")
        if success_line:
            log(f"[+] WINRM SUCCESS: {ip}")
            log(f"    RAW: {success_line}")
            pwned = "Pwn3d!" in winrm_out
            successes.append(["WINRM", ip, "5985", args.username, "YES", "YES" if pwned else "NO"])
        else:
            log(f"[-] WINRM FAILED: {ip}")
            log(f"    OUTPUT:\n{winrm_out}")

    if args.rdp:
        rdp_cmd = f"nxc rdp {ip} -u {args.username} -p '{args.password}' -d {args.domain}"
        rdp_out = run_cmd(rdp_cmd)
        success_line = parse_success(rdp_out, ip, "RDP")
        if success_line:
            log(f"[+] RDP SUCCESS: {ip}")
            log(f"    RAW: {success_line}")
            successes.append(["RDP", ip, "3389", args.username, "YES", "N/A"])
        else:
            log(f"[-] RDP FAILED: {ip}")
            log(f"    OUTPUT:\n{rdp_out}")

# -------------------------------
# Argument parsing
# -------------------------------
parser = argparse.ArgumentParser(description="Parallel SMB, WinRM, and RDP enumeration using crackmapexec and nxc.")
parser.add_argument("-i", "--ips", nargs="+", required=True, help="List of IPs or ranges (e.g. 192.168.1.100-105)")
parser.add_argument("-u", "--username", required=True, help="Username")
parser.add_argument("-p", "--password", required=True, help="Password (quote if needed)")
parser.add_argument("-d", "--domain", required=True, help="Domain")
parser.add_argument("--smb", action="store_true", help="Enable SMB enumeration")
parser.add_argument("--winrm", action="store_true", help="Enable WinRM enumeration")
parser.add_argument("--rdp", action="store_true", help="Enable RDP enumeration")
parser.add_argument("--threads", type=int, default=MAX_THREADS, help=f"Max parallel threads (default {MAX_THREADS})")

args = parser.parse_args()

# -------------------------------
# Prep
# -------------------------------
ip_list = expand_ips(args.ips)
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
outfile = f"host_enum_{timestamp}.txt"

log(f"===== Host Enumeration Started at {timestamp} =====")

# -------------------------------
# Parallel Execution
# -------------------------------
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    futures = {executor.submit(enumerate_host, ip, args): ip for ip in ip_list}
    for future in as_completed(futures):
        ip = futures[future]
        try:
            future.result()
        except Exception as e:
            log(f"[!] ERROR on {ip}: {e}")

# -------------------------------
# Final summary table
# -------------------------------
log("\n===== Enumeration Complete =====")

if successes:
    log("\n=== SUCCESS SUMMARY TABLE ===\n")

    # Table header
    header = ["Protocol", "IP", "Port", "Username", "Auth Success", "Pwn3d!"]
    col_widths = [len(h) for h in header]

    # Measure column widths
    for row in successes:
        for i, value in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(value)))

    # Format row function
    def format_row(row):
        return " | ".join(str(value).ljust(col_widths[i]) for i, value in enumerate(row))

    # Print header
    log(format_row(header))
    log("-+-".join("-" * w for w in col_widths))

    # Print rows
    for row in successes:
        log(format_row(row))
else:
    log("No successful authentications were detected.")