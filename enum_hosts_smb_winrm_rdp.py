#!/usr/bin/env python3
"""
Improved enum_hosts_smb_winrm_rdp.py

Changes vs. original
--------------------
* **Domain is now optional** – If omitted, no `-d` flag is passed to the underlying tools.
* Switched to `shlex.quote` everywhere to avoid shell‑injection issues.
* Minor readability tweaks (helper for building auth flags).
* ** Consider using local for domain for nxc depending on the use-case

Usage examples
--------------
With domain:
    python3 enum_hosts_smb_winrm_rdp.py -i 192.168.211.245-249 192.168.211.189 -u alice -p "P@ssw0rd" -d test.com --smb --winrm --rdp --threads 10

Without domain:
    python3 enum_hosts_smb_winrm_rdp.py -i 192.168.211.245-249 -u alice -p "P@ssw0rd" --smb
"""

import subprocess
import datetime
import argparse
import re
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# -------------------------------
# Config
# -------------------------------
MAX_THREADS = 10
CMD_TIMEOUT = 30  # seconds
log_lock = Lock()
successes = []

# -------------------------------
# Helpers
# -------------------------------

def log(line: str):
    """Thread‑safe logger to both stdout and file."""
    with log_lock:
        with open(outfile, "a") as f:
            f.write(line + "\n")
        print(line)


def run_cmd(cmd: str) -> str:
    """Execute shell command and return stdout, logging the invocation."""
    log(f"[>] Executing: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=CMD_TIMEOUT)
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"


def expand_ips(ip_input_list):
    """Expand dash‑separated IPv4 ranges into a flat list."""
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


def parse_success(output: str, ip: str, proto: str):
    """Look for CME/NXC success lines."""
    for line in output.splitlines():
        if proto in line and ip in line and "[+]" in line:
            return line
    return None


def build_auth_flags(args):
    """Return the authentication arguments string, omitting -d when not provided."""
    flags = f"-u {shlex.quote(args.username)} -p {shlex.quote(args.password)}"
    if args.domain:
        flags += f" -d {shlex.quote(args.domain)}"
    return flags

# -------------------------------
# Main per‑host worker
# -------------------------------

def enumerate_host(ip, args):
    log(f"\n--- Enumerating {ip} ---")
    auth_flags = build_auth_flags(args)

    if args.smb:
        smb_cmd = f"crackmapexec smb {shlex.quote(ip)} {auth_flags} --continue-on-success"
        smb_out = run_cmd(smb_cmd)
        success_line = parse_success(smb_out, ip, "SMB")
        if success_line:
            log(f"[+] SMB SUCCESS: {ip}")
            pwned = "Pwn3d!" in smb_out
            successes.append(["SMB", ip, "445", args.username, "YES", "YES" if pwned else "NO"])
        else:
            log(f"[-] SMB FAILED: {ip}")

    if args.winrm:
        winrm_cmd = f"crackmapexec winrm {shlex.quote(ip)} {auth_flags} --continue-on-success"
        winrm_out = run_cmd(winrm_cmd)
        success_line = parse_success(winrm_out, ip, "WINRM")
        if success_line:
            log(f"[+] WINRM SUCCESS: {ip}")
            pwned = "Pwn3d!" in winrm_out
            successes.append(["WINRM", ip, "5985", args.username, "YES", "YES" if pwned else "NO"])
        else:
            log(f"[-] WINRM FAILED: {ip}")

    if args.rdp:
        rdp_cmd = f"nxc rdp {shlex.quote(ip)} {auth_flags}"
        rdp_out = run_cmd(rdp_cmd)
        success_line = parse_success(rdp_out, ip, "RDP")
        if success_line:
            log(f"[+] RDP SUCCESS: {ip}")
            successes.append(["RDP", ip, "3389", args.username, "YES", "N/A"])
        else:
            log(f"[-] RDP FAILED: {ip}")

# -------------------------------
# Argument parsing
# -------------------------------
parser = argparse.ArgumentParser(
    description="Parallel SMB, WinRM, and RDP enumeration using crackmapexec and nxc. Domain is optional.")
parser.add_argument("-i", "--ips", nargs="+", required=True, help="IPs or ranges (e.g. 192.168.1.100-105)")
parser.add_argument("-u", "--username", required=True, help="Username")
parser.add_argument("-p", "--password", required=True, help="Password (quote if needed)")
parser.add_argument("-d", "--domain", default="", help="Domain (omit for local accounts)")
parser.add_argument("--smb", action="store_true", help="Enable SMB enumeration")
parser.add_argument("--winrm", action="store_true", help="Enable WinRM enumeration")
parser.add_argument("--rdp", action="store_true", help="Enable RDP enumeration")
parser.add_argument("--threads", type=int, default=MAX_THREADS, help=f"Max parallel threads (default {MAX_THREADS})")

args = parser.parse_args()

# -------------------------------
# Prep & logging setup
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
    header = ["Protocol", "IP", "Port", "Username", "Auth Success", "Pwn3d!"]
    col_widths = [max(len(h), max((len(str(row[i])) for row in successes), default=0)) for i, h in enumerate(header)]

    def fmt_row(r):
        return " | ".join(str(r[i]).ljust(col_widths[i]) for i in range(len(header)))

    log(fmt_row(header))
    log("-+-".join("-" * w for w in col_widths))
    for row in successes:
        log(fmt_row(row))
else:
    log("No successful authentications were detected.")