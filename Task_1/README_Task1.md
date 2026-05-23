# 🌐 Task 1 — Basic Network Packet Sniffer

> **CodeAlpha Cyber Security Internship**  
> Cross-platform network packet capture, analysis, and logging tool built with Scapy.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Files](#output-files)
- [How It Works](#how-it-works)
- [Protocols Captured](#protocols-captured)
- [Fixes From Original Code](#fixes-from-original-code)
- [Sample Output](#sample-output)
- [Troubleshooting](#troubleshooting)

---

## Overview

`Task1_Perfect.py` is a real-time network packet sniffer that captures live traffic on your machine, analyzes each packet's structure, displays key fields in a color-coded terminal, and writes logs in three formats (TXT, CSV, PCAP) for later analysis.

It is fully **cross-platform** — runs on Windows, Linux, and macOS without any code changes.

---

## Features

| Feature | Description |
|---|---|
| 🖥️ Cross-platform | Windows, Linux, macOS — one codebase |
| 📡 Multi-protocol | TCP, UDP, ICMP, ARP, and OTHER |
| 📄 Multi-format logging | TXT, CSV, PCAP (Wireshark-compatible) |
| 🔍 Payload decoding | Raw bytes → readable ASCII (non-printable → `.`) |
| 🔢 Live packet counter | Displays `#1`, `#2`, `#3`... in real time |
| 🧠 Smart interface selection | Auto-picks best active NIC (Wi-Fi > Ethernet) |
| 📊 Exit summary | Per-protocol bar chart on Ctrl+C |
| 🛡️ Safe CSV handling | Header written only once; appends on restart |

---

## Requirements

| Package | Version | Purpose |
|---|---|---|
| `scapy` | ≥ 2.5 | Packet capture and analysis |
| `colorama` | ≥ 0.4 | Color-coded terminal output |
| `netifaces` | ≥ 0.11 *(optional)* | Better interface detection on Linux/macOS |

**System requirements:**
- Python 3.7+
- **Windows:** Run as **Administrator**
- **Linux / macOS:** Run with **`sudo`**
- Npcap (Windows) or libpcap (Linux/macOS) installed

---

## Installation

### Step 1 — Install Python packages

```bash
pip install scapy colorama
```

For better interface detection on Linux/macOS (optional but recommended):

```bash
pip install netifaces
```

### Step 2 — Install packet capture library

**Windows:**
Download and install [Npcap](https://npcap.com/#download) — choose "WinPcap API-compatible mode" during install.

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libpcap-dev
```

**macOS:**
```bash
brew install libpcap
```

---

## Usage

### Windows (run as Administrator)
```bash
python Task1_Perfect.py
```

### Linux / macOS (requires sudo for raw socket access)
```bash
sudo python3 Task1_Perfect.py
```

### Stop capturing
Press **`Ctrl+C`** — the tool will save the PCAP file and print a summary before exiting.

---

## Output Files

All logs are saved inside a `packet_logs/` folder created in the same directory as the script.

```
packet_logs/
├── log.txt         ← Human-readable packet log (one line per packet)
├── log.csv         ← Spreadsheet-compatible (Time, Protocol, IPs, Ports, Payload)
├── payloads.txt    ← Extracted payload data only (packets with Raw layer)
└── capture.pcap    ← Binary capture — open in Wireshark for full analysis
```

### `log.txt` example
```
[2026-05-22 14:32:01] #1 TCP 192.168.1.5:54312  -> 142.250.80.46:443 | Payload: None
[2026-05-22 14:32:01] #2 UDP 192.168.1.1:53     -> 192.168.1.5:52101 | Payload: ..dns..
[2026-05-22 14:32:02] #3 ARP 192.168.1.1:-      -> 192.168.1.255:- | Payload: None
```

### `log.csv` columns
| Time | Protocol | Source IP | Src Port | Destination IP | Dst Port | Payload |
|---|---|---|---|---|---|---|
| 2026-05-22 14:32:01 | TCP | 192.168.1.5 | 54312 | 142.250.80.46 | 443 | None |

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROGRAM FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. STARTUP                                                     │
│     └─ Detect OS (Windows / Linux / macOS)                     │
│     └─ Auto-select best network interface                       │
│     └─ Initialize log files (CSV header written once)          │
│                                                                 │
│  2. CAPTURE LOOP  (scapy sniff)                                 │
│     └─ Filter: "ip or arp"                                      │
│     └─ For each packet:                                         │
│         ├─ Detect protocol (TCP / UDP / ICMP / ARP)            │
│         ├─ Extract src IP, dst IP, src port, dst port           │
│         ├─ Decode payload (Raw bytes → ASCII)                   │
│         ├─ Print to terminal (color-coded)                      │
│         └─ Append to TXT, CSV, payloads.txt                    │
│                                                                 │
│  3. SHUTDOWN  (Ctrl+C)                                          │
│     └─ Save all packets to capture.pcap (Wireshark format)     │
│     └─ Print per-protocol summary with bar chart               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Interface Auto-Selection Priority

```
Windows:   Wi-Fi (with IPv4) > Ethernet (with IPv4) > others
Linux:     wlan* > eth*/en* > others   (via netifaces)
macOS:     en0/en1 > others            (via netifaces)
Fallback:  scapy conf.iface (default)
Excluded:  loopback, VMware, VirtualBox, tunnel, Bluetooth
```

---

## Protocols Captured

| Protocol | Layer | What's captured |
|---|---|---|
| **TCP** | Transport | Source/dest IP, port, flags, payload |
| **UDP** | Transport | Source/dest IP, port, payload |
| **ICMP** | Network | Source/dest IP, type/code |
| **ARP** | Link | Sender/target IP (who-has requests) |
| **OTHER** | Network | Any other IP protocol |

> **Payload note:** Payloads are only captured when the packet contains a `Raw` layer (application data). Control packets like TCP `SYN`/`ACK` have no payload — this is normal.

---

## Fixes From Original Code

The following issues were found in the original submissions and fixed in this version:

| # | Issue | Original | Fixed |
|---|---|---|---|
| 1 | **Platform support** | `from scapy.arch.windows import get_windows_if_list` — crashes on Linux/macOS | OS detection with platform-specific path |
| 2 | **Missing protocols** | `if not pkt.haslayer(Raw): return` — skips ~60% of traffic | Captures all IP/ARP packets regardless of payload |
| 3 | **Unreadable payloads** | Base64-encoded (`U1NIIFJ0YTpSb290...`) | Human-readable ASCII with `.` for non-printable bytes |
| 4 | **Exception handling** | Generic `except Exception` masks real errors | Specific `PermissionError` + `Exception` with clear messages |
| 5 | **CSV corruption** | Header written on every run — overwrites existing data | Atomic guard: header written only if file is new/empty |
| 6 | **No packet counter** | No way to see how many packets captured | Live `#N` counter on every packet line |
| 7 | **No ARP capture** | ARP packets silently ignored | `if IP not in pkt and ARP not in pkt: return` added |

---

## Sample Output

```
  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
  ...
       SNIFFER  —  CodeAlpha Cyber Security Internship

[INFO] Auto-selected: Intel(R) Wi-Fi 6 AX201 (192.168.1.5)

[SNIFFING] Interface : Intel(R) Wi-Fi 6 AX201
[SNIFFING] Filter    : IP and ARP packets
[SNIFFING] Press Ctrl+C to stop

[#1] [2026-05-22 14:32:01]
  Protocol : TCP
  Source   : 192.168.1.5:54312  →  142.250.80.46:443

[#2] [2026-05-22 14:32:01]
  Protocol : UDP
  Source   : 192.168.1.5:52101  →  8.8.8.8:53
  Payload  : .....google.com.....

[#3] [2026-05-22 14:32:02]
  Protocol : ARP
  Source   : 192.168.1.1:-  →  192.168.1.255:-

^C

[!] Sniffing stopped by user.

╔══════════════════════════════╗
║      CAPTURE SUMMARY         ║
╚══════════════════════════════╝
  Total packets : 127
  TCP      : ████████████████████████████████ 89
  UDP      : ████████████ 28
  ICMP     : ████ 7
  ARP      : ██ 3

  Logs saved in : /home/user/packet_logs
  ├─ log.txt
  ├─ log.csv
  ├─ payloads.txt
  └─ capture.pcap
```

---

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| `PermissionError` | Not running as admin/sudo | Windows: Run as Administrator · Linux/macOS: `sudo python3 ...` |
| `No valid IPv4 interface found` | All interfaces inactive or filtered | Check `ipconfig` / `ifconfig` and make sure a NIC is connected |
| `ImportError: scapy` | Package not installed | `pip install scapy` |
| `ImportError: colorama` | Package not installed | `pip install colorama` |
| `No packets captured` | Wrong interface selected | Manually specify: edit `iface = "eth0"` in `main()` |
| PCAP not opening in Wireshark | Wireshark not installed | Download from [wireshark.org](https://www.wireshark.org/) |
| Npcap error on Windows | Npcap not installed or wrong version | Reinstall [Npcap](https://npcap.com/#download) with WinPcap compatibility |

---

## Legal & Ethical Notice

> ⚠️ **Only capture traffic on networks you own or have explicit written permission to monitor.**  
> Unauthorized packet capture is illegal in most jurisdictions.  
> This tool is intended for **educational purposes** and authorized security testing only.

---

## Project Structure

```
Task1_Perfect.py          ← Main script (this file)
packet_logs/              ← Auto-created on first run
    ├── log.txt
    ├── log.csv
    ├── payloads.txt
    └── capture.pcap
README_Task1_NetworkSniffer.md   ← This file
```

---

*CodeAlpha Cyber Security Internship — Task 1*  
*Cross-Platform Network Packet Sniffer*
