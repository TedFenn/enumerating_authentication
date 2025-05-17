# Host Enumeration Toolkit

Parallel SMB, WinRM, and RDP authentication tester powered by CrackMapExec & NXC.

# Overview

enum_hosts_smb_winrm_rdp.py is a Python 3 utility that performs rapid, multi‑threaded credential validation against Windows hosts over SMB (445), WinRM (5985/5986), and RDP (3389).  It is designed for blue‑team validation, penetration‑testing lab automation, and other legitimate security workflows where you need to quickly determine which targets accept a given set of credentials.

This tool is NOT intended for malicious activity. Please read the Ethical Usage Notice before continuing.

Features

🔍 Parallel scanning with a configurable thread‑pool (default 10).

🎯 Flexible target syntax – single IPs or dash‑separated ranges (192.168.1.100-120).

🔐 Credential reuse check across SMB, WinRM, and RDP in a single run.

📋 Flat‑file log plus an in‑terminal success summary table for quick triage.

📝 Built‑in usage banner & examples for ease of scripting.

# Using the Web User Interface
- python3 -m venv toolkit
- source toolkit/bin/activate
- pip install flask
- python3 app.py
- Access on port localhost:5000

# Quick Start with CLI

python3 enum_hosts_smb_winrm_rdp.py \
  -i 192.168.124.245-249 192.168.124.191 192.168.124.189 \
  -u alice \
  -p 'P@ssw0rd!' \
  -d CORP.LOCAL \
  --smb --winrm --rdp \
  --threads 8

# The script above will:

- Expand IP ranges. 
- Spawn up to 8 worker threads. Default is 10.
- Run the appropriate crackmapexec or nxc command per protocol.
- Log detailed output to host_enum_YYYY-MM-DD_HH-MM-SS.txt.
- Print a concise success table at the end.

# Flags:
- -i, --ips | One or more IPs or dash‑separated ranges
- -u, --username | Username to authenticate with
- -p, --password | Password (wrap in quotes if it contains special chars)
- -d, --domain | Windows/AD domain
- --smb | Enable SMB authentication test
- --winrm | Enable WinRM authentication test
- --rdp | Enable RDP authentication test
- --threads | Max concurrent threads (default 10)

# Ethical Usage Notice

This software is released solely for lawful security research, penetration‑testing in environments where you have explicit authorization, blue‑team validation, and educational purposes.
