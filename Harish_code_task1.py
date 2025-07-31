import os
import base64
import csv
from datetime import datetime
from collections import defaultdict
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from scapy.arch.windows import get_windows_if_list
from colorama import Fore, init

# Initialize color output
init(autoreset=True)

# === Log Directory Setup ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "packet_logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_TXT = os.path.join(LOG_DIR, "log.txt")
LOG_CSV = os.path.join(LOG_DIR, "log.csv")
LOG_PCAP = os.path.join(LOG_DIR, "capture.pcap")
LOG_PAYLOAD = os.path.join(LOG_DIR, "payloads.txt")

captured_packets = []
protocol_counter = defaultdict(int)
sniffing = False
interface_selected = None

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.attributes("-fullscreen", True)
root.configure(bg="black")

# Initialize GUI variable AFTER root is created
show_payloads = tk.BooleanVar(master=root, value=True)

def write_csv_header():
    with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "Time", "Protocol", "Source IP", "Src Port", "Destination IP", "Dst Port", "Payload"
        ])

def analyze_packet(pkt):
    global captured_packets

    if not pkt.haslayer(IP):
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = pkt[IP].src
    dst = pkt[IP].dst
    protocol = "OTHER"
    sport = "-"
    dport = "-"
    payload = "None"

    if pkt.haslayer(TCP):
        protocol = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    if pkt.haslayer(Raw):
        try:
            raw_data = pkt[Raw].load
            payload = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_data)
        except:
            payload = "<Binary Data>"

    log = f"[{now}] {protocol} {src}:{sport} -> {dst}:{dport}"

    # Console log
    print(Fore.CYAN + f"\n[Time: {now}]")
    print(Fore.YELLOW + f" Protocol: {protocol}")
    print(Fore.GREEN + f" Source: {src}:{sport} -> {dst}:{dport}")
    if show_payloads.get():
        print(Fore.MAGENTA + f" Payload: {payload}")

    # GUI log
    log_output.insert(tk.END, log + "\n")
    if show_payloads.get():
        log_output.insert(tk.END, f"Payload: {payload}\n\n")
    log_output.see(tk.END)

    # Save logs
    with open(LOG_TXT, "a", encoding="utf-8") as f:
        f.write(f"{log} | Payload: {payload}\n")

    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([now, protocol, src, sport, dst, dport, payload])

    with open(LOG_PAYLOAD, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {src}:{sport} -> {dst}:{dport}\n{payload}\n\n")

    captured_packets.append(pkt)
    protocol_counter[protocol] += 1

def get_best_interface():
    interfaces = get_windows_if_list()

    def score(iface):
        desc = iface['description'].lower()
        ips = iface.get('ips', [])
        has_ipv4 = any('.' in ip for ip in ips)

        if "loopback" in desc or "vmware" in desc or "virtual" in desc:
            return -1
        if "wi-fi" in desc or "wireless" in desc:
            return 3 if has_ipv4 else 2
        if "ethernet" in desc:
            return 2 if has_ipv4 else 1
        return 0

    sorted_ifs = sorted(interfaces, key=score, reverse=True)

    for iface in sorted_ifs:
        ips = iface.get('ips', [])
        ip = next((ip for ip in ips if '.' in ip), None)
        if ip:
            print(Fore.GREEN + f"[INFO] Auto-selected: {iface['description']} ({ip})")
            return iface['name']

    raise Exception("❌ No valid IPv4 interface found.")

def sniff_packets():
    global sniffing
    sniffing = True
    write_csv_header()
    try:
        sniff(iface=interface_selected, prn=analyze_packet, store=False, stop_filter=lambda x: not sniffing)
    except PermissionError:
        messagebox.showerror("Permission Error", "Run as Administrator to sniff packets.")
    except Exception as e:
        messagebox.showerror("Sniffing Error", str(e))

def start_sniffing():
    global interface_selected, sniff_thread, sniffing
    interface_selected = interface_combo.get()
    if not interface_selected:
        messagebox.showwarning("Select Interface", "Please select a network interface.")
        return
    if sniffing:
        messagebox.showinfo("Already Running", "Sniffing is already in progress.")
        return
    log_output.delete(1.0, tk.END)
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

def stop_sniffing():
    global sniffing
    if sniffing:
        sniffing = False
        wrpcap(LOG_PCAP, captured_packets)
        summary = f"\n=== Capture Summary ===\nTotal Packets: {len(captured_packets)}\n"
        for proto, count in protocol_counter.items():
            summary += f"{proto}: {count}\n"
        summary += f"\nLogs saved in: {LOG_DIR}"
        messagebox.showinfo("Capture Stopped", summary)
    else:
        messagebox.showinfo("Not Running", "No active sniffing to stop.")

def view_log(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            content = f.read()
        log_output.delete(1.0, tk.END)
        log_output.insert(tk.END, content)
    except FileNotFoundError:
        messagebox.showwarning("Log Not Found", f"{file} does not exist.")

def get_interfaces():
    interfaces = get_windows_if_list()
    return [
        i['name'] for i in interfaces
        if i['ips'] and all(x not in i['description'].lower() for x in ['loopback', 'virtual', 'vmware', 'tunnel'])
    ]

# GUI Layout
frame_top = tk.Frame(root, bg="black")
frame_top.pack(pady=10)

tk.Label(frame_top, text="Select Interface: ", fg="lime", bg="black", font=("Consolas", 12)).pack(side=tk.LEFT)
interface_combo = ttk.Combobox(frame_top, values=get_interfaces(), width=60)
interface_combo.pack(side=tk.LEFT, padx=10)
if len(interface_combo['values']) == 1:
    interface_combo.current(0)

payload_toggle = tk.Checkbutton(frame_top, text="Show Payloads", variable=show_payloads, onvalue=True, offvalue=False, bg="black", fg="lime", font=("Consolas", 12), selectcolor="black")
payload_toggle.pack(side=tk.LEFT, padx=10)

frame_buttons = tk.Frame(root, bg="black")
frame_buttons.pack(pady=10)

btn_style = {"bg": "#111", "fg": "lime", "font": ("Consolas", 11), "width": 15, "relief": tk.RIDGE}
tk.Button(frame_buttons, text="Start Sniffing", command=start_sniffing, **btn_style).pack(side=tk.LEFT, padx=10)
tk.Button(frame_buttons, text="Stop Sniffing", command=stop_sniffing, **btn_style).pack(side=tk.LEFT, padx=10)
tk.Button(frame_buttons, text="View Text Log", command=lambda: view_log(LOG_TXT), **btn_style).pack(side=tk.LEFT, padx=10)
tk.Button(frame_buttons, text="View CSV Log", command=lambda: view_log(LOG_CSV), **btn_style).pack(side=tk.LEFT, padx=10)
tk.Button(frame_buttons, text="Exit", command=root.destroy, **btn_style).pack(side=tk.LEFT, padx=10)

log_output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=180, height=40, bg="black", fg="lime", font=("Consolas", 10))
log_output.pack(pady=10)

root.mainloop()
