[README_Overall.md](https://github.com/user-attachments/files/28175137/README_Overall.md)
# 🛡️ CodeAlpha Cyber Security Internship

> \*\*Intern:\*\* \[Harish V]  
> \*\*Program:\*\* CodeAlpha Cyber Security Internship  
> \*\*Domain:\*\* Cyber Security  
> \*\*Tasks Completed:\*\* Task 1, Task 2, Task 3 (3 out of 4)  
---

## 📋 Table of Contents

* [About the Internship](#about-the-internship)
* [Repository Structure](#repository-structure)
* [Task 1 — Basic Network Sniffer](#task-1--basic-network-sniffer)
* [Task 2 — Phishing Awareness Training](#task-2--phishing-awareness-training)
* [Task 3 — Secure Coding Review](#task-3--secure-coding-review)
* [Skills \& Technologies Used](#skills--technologies-used)
* [How to Run Everything](#how-to-run-everything)
* [Key Learnings](#key-learnings)
* [Acknowledgements](#acknowledgements)

\---

## About the Internship

CodeAlpha is a software development company focused on building secure and resilient systems. This internship program provides hands-on experience in real-world cybersecurity practices — not just theory.

Interns are expected to complete a minimum of **2 out of 4 tasks** to receive a completion certificate. I completed **3 tasks**, covering:

* Network traffic analysis and packet capture
* Security awareness education and training
* Secure code review and vulnerability remediation

Each task required researching the relevant attack vectors, writing production-quality code or content, and documenting findings clearly — skills that directly mirror what security professionals do daily in the field.

\---

## Repository Structure

```
CodeAlpha\_CyberSecurity/
│
├── Task1\_NetworkSniffer/
│   ├── Task1\_Perfect.py                  ← Main sniffer script
│   ├── README\_Task1\_NetworkSniffer.md    ← Task-specific README
│   └── packet\_logs/                      ← Auto-created at runtime
│       ├── log.txt
│       ├── log.csv
│       ├── payloads.txt
│       └── capture.pcap
│
├── Task2\_PhishingTraining/
│   ├── Task2\_Phishing\_Awareness\_Training.pptx   ← 16-slide presentation
│   └── README\_Task2\_PhishingTraining.md          ← Task-specific README
│
├── Task3\_SecureCoding/
│   ├── Task3\_Perfect\_SecureCoding.py     ← Secure Flask application
│   ├── users\_secure.db                   ← SQLite DB (auto-created at runtime)
│   └── README\_Task3\_SecureCoding.md      ← Task-specific README
│
└── README\_Overall.md                     ← This file (overall overview)
```

\---

## Task 1 — Basic Network Sniffer

### What the task asked for

> Build a Python program to capture network traffic packets, analyze their structure and content, learn how data flows through the network, use libraries like `scapy` or `socket`, and display useful information such as source/destination IPs, protocols, and payloads.

### What I built

A real-time, cross-platform network packet sniffer using **Scapy** that captures live traffic, analyzes each packet's structure, and logs everything to three different file formats for later analysis.

### Why I built it this way

The task asked for packet analysis, but I wanted the tool to be genuinely useful — not just a script that runs on one OS and misses half the traffic. The key design decisions were:

**Cross-platform from the ground up.** Most beginner Scapy code uses `from scapy.arch.windows import get\_windows\_if\_list` which crashes immediately on Linux or macOS. I used `platform.system()` to branch into OS-specific interface detection, with a `netifaces` fallback on Unix systems and Scapy's `conf.iface` as a final safety net. This means the same script works in any environment.

**Capturing all protocols, not just data payloads.** A common mistake is filtering to only packets that have a `Raw` layer (actual payload data). This silently discards control traffic — TCP handshakes, ICMP pings, ARP requests — which makes up the majority of packets on most networks. My filter captures anything with an IP or ARP layer, then checks for a payload separately. This gives a complete picture of network activity.

**Human-readable payload decoding.** Raw packet bytes are meaningless at a glance. I wrote a `decode\_payload()` function that converts each byte to its ASCII character if printable (32–126), or replaces it with a `.` otherwise. This is the same approach Wireshark uses for its "ASCII" view — you can immediately read strings like `GET /index.html HTTP/1.1` in DNS or HTTP traffic without any separate decoding step.

**Three log formats for different use cases.** TXT is for human reading, CSV is for loading into Excel or pandas for analysis, and PCAP is the industry-standard binary format that opens in Wireshark for deep packet inspection. Saving all three means the data is accessible at every skill level.

### Key features

|Feature|Description|
|-|-|
|Cross-platform|Windows, Linux, macOS — one codebase|
|Multi-protocol|TCP, UDP, ICMP, ARP|
|Live packet counter|`#1`, `#2`, `#3`... displayed in real time|
|Smart interface selection|Auto-picks best active NIC (Wi-Fi > Ethernet)|
|Multi-format logs|TXT + CSV + PCAP (Wireshark) + payloads.txt|
|ASCII payload decoding|Human-readable, non-printable bytes shown as `.`|
|Exit summary|Per-protocol bar chart printed on Ctrl+C|

### How to run

```bash
pip install scapy colorama

# Windows (run as Administrator)
python Task1\_Perfect.py

# Linux / macOS (requires sudo)
sudo python3 Task1\_Perfect.py
```

### Sample output

```
\[#1] \[2026-05-22 14:32:01]
  Protocol : TCP
  Source   : 192.168.1.5:54312  →  142.250.80.46:443

\[#2] \[2026-05-22 14:32:01]
  Protocol : UDP
  Source   : 192.168.1.5:52101  →  8.8.8.8:53
  Payload  : .....google.com.....

╔══════════════════════════════╗
║      CAPTURE SUMMARY         ║
╚══════════════════════════════╝
  Total packets : 127
  TCP      : ████████████████████████████████ 89
  UDP      : ████████████ 28
  ICMP     : ████ 7
  ARP      : ██ 3
```

\---

## Task 2 — Phishing Awareness Training

### What the task asked for

> Create a presentation or online module focused on phishing attacks. Explain how to recognize phishing emails and fake websites. Educate about social engineering tactics. Provide best practices and tips to avoid falling victim. Include real-world examples and interactive quizzes for better engagement.

### What I built

A **16-slide professional PowerPoint presentation** (.pptx) that serves as a complete phishing awareness training module — suitable for a corporate lunch-and-learn, a classroom session, or a security awareness campaign.

### Why I built it this way

The task explicitly asked for real-world examples and interactive quizzes — two things that require research and careful design, not just writing down definitions.

**Real-world case studies with concrete details.** Generic advice like "don't click suspicious links" is easy to ignore. People remember specific, named incidents. I included three major attacks with dates, losses, victim names, and — most importantly — a clear lesson from each one. The cases I chose span different phishing types: vendor invoice fraud (email phishing), credential theft (spear phishing), and phone-based social engineering (vishing). Together they show that phishing isn't one thing — it's a category of attack that adapts to the target.

**The Google/Facebook case** ($100 million lost to fake invoices) shows that even the world's most technically sophisticated companies are vulnerable to social engineering.  
**The DNC case** (50,000 emails stolen via a fake Google login page) shows that a single click from one person can have consequences that reach millions.  
**The Twitter case** ($120,000 in bitcoin scammed from hijacked celebrity accounts) shows that attackers don't always need to break through technical defenses — they call employees on the phone and ask for access.

**An interactive quiz built around real detection skills.** The five quiz scenarios aren't hypothetical — they are based on real phishing techniques. Each one tests a specific skill: spotting a homograph domain (`g00gle.com`), recognizing vishing, identifying smishing, detecting Business Email Compromise, and understanding how subdomain spoofing works (`amazon.com.account-verify.xyz`). The last one is particularly important because many people incorrectly think seeing `amazon.com` anywhere in a URL means the site is safe.

**Professional design that respects the audience.** Security training has a reputation for being boring. A plain text document with bullet points gets skimmed. I used a Cherry Bold color palette (deep red + navy + gold), varied slide layouts, annotated mock-ups, and real icons to create something that looks like it belongs in a real corporate training program.

### Presentation structure

```
Section 1 — Understanding Phishing      (Slides 1–5)
  What is phishing, its impact, and 6 types of attacks

Section 2 — Recognizing Phishing        (Slides 6–8)
  Phishing email red flags, fake website detection,
  and 5 social engineering tactics

Section 3 — Real-World Case Studies     (Slides 9–10)
  Google \& Facebook ($100M), DNC (50K emails),
  Twitter ($120K Bitcoin)

Section 4 — Best Practices \& Defense   (Slides 11–12)
  6 actionable defensive strategies

Section 5 — Interactive Quiz            (Slides 13–14)
  5 phishing detection scenarios with instant answers

Closing                                 (Slides 15–16)
  3 key takeaways + contact information
```

### Key content highlights

* **6 attack types covered:** Email phishing, Spear phishing, Vishing, Smishing, Whaling, Clone phishing
* **5 social engineering tactics:** Urgency, Fear, Greed/Bait, Authority, Empathy
* **6 defensive strategies:** Strong passwords, 2FA, hover before clicking, software updates, training, reporting
* **3 real-world cases** with verified facts, losses, and lessons
* **5 quiz scenarios** targeting the most common detection failures

### How to open

```
Open Task2\_Phishing\_Awareness\_Training.pptx with:
  • Microsoft PowerPoint
  • Google Slides (upload at slides.google.com)
  • LibreOffice Impress
  • Apple Keynote
```

\---

## Task 3 — Secure Coding Review

### What the task asked for

> Select a programming language and application to audit. Perform a code review to identify security vulnerabilities. Use static analyzers or manual inspection methods. Provide recommendations and best practices for secure coding. Document findings and suggest remediation steps for safer code.

### What I built

A **complete security audit** of a vulnerable Flask login application, producing a fixed, production-ready version that addresses all identified vulnerabilities. The original vulnerable code (`Task3.py`) was used as the audit target. The output is a secure version (`Task3\_Perfect\_SecureCoding.py`) with inline documentation of every vulnerability and its fix.

### Why I built it this way

The original code was a deceptively simple 20-line Flask app — short enough that vulnerabilities are easy to miss on a quick read, but serious enough that deploying it would expose any users to real harm.

**I chose to audit a login endpoint specifically because authentication is the most attacked surface in any web application.** Every vulnerability I identified is from real attack playbooks used against real websites today.

**SQL Injection (Critical) — the most important fix.**  
The original code used Python's f-string to build the SQL query directly from user input: `f"SELECT \* FROM users WHERE username='{username}'"`. This is the textbook definition of SQL injection. An attacker enters `' OR '1'='1` as the username and the WHERE clause becomes always-true, granting instant access to the first account in the database (usually admin). I replaced this with a parameterized query using `?` placeholders — the database driver then handles the escaping, making it structurally impossible for user input to be interpreted as SQL code.

**Password hashing (High) — the fix most developers skip.**  
Storing passwords as plaintext is illegal under GDPR and most data protection frameworks, yet it is extremely common in tutorial code. I implemented bcrypt — the industry standard for password storage. bcrypt is specifically designed to be slow (computationally expensive) which makes it resistant to cracking even if the database is stolen. The original password and the hash cannot be compared directly — you can only verify a plaintext attempt against a stored hash. This means even the developer cannot read users' passwords.

**CSRF protection (High) — often overlooked.**  
Without CSRF tokens, an attacker can host a page that auto-submits the login form to your site using the victim's browser session. I generated a `secrets.token\_hex(32)` token on page load, stored it in the server-side session, embedded it in a hidden form field, and validated it on every POST using `secrets.compare\_digest()` — a timing-safe comparison that prevents side-channel attacks on the token itself.

**Rate limiting (High) — the difference between a nuisance and a breach.**  
Without any throttling, an attacker can try millions of password combinations programmatically. I implemented per-IP attempt tracking: after 5 failed logins, the IP is locked out for 5 minutes. This makes brute-force attacks impractical — at 5 attempts per 5 minutes, it would take years to try even a small dictionary.

**The other four fixes** (generic error messages, input validation, debug mode, security headers) represent the defense-in-depth mindset — no single fix is sufficient; layering multiple controls means an attacker who bypasses one still faces others.

### Vulnerabilities found and fixed

|#|Vulnerability|Severity|Fix Applied|
|-|-|-|-|
|1|SQL Injection|🔴 Critical|Parameterized queries|
|2|Plaintext password storage|🟠 High|bcrypt hashing|
|3|No CSRF protection|🟠 High|Session token + form validation|
|4|No brute force protection|🟠 High|5-attempt / 5-min IP lockout|
|5|Username enumeration|🟡 Medium|Generic error messages|
|6|No input validation|🟡 Medium|Length caps + regex whitelist|
|7|Debug mode in production|🟡 Medium|`FLASK\_DEBUG` environment variable|
|8|Missing security headers|🟢 Low|`after\_request` hook with 5 headers|

### How to run

```bash
pip install flask bcrypt

python Task3\_Perfect\_SecureCoding.py
# Visit: http://127.0.0.1:5000

# Demo credentials:
# admin    / SecurePass@99
# testuser / Hello#World1
```

### Verify the SQL injection is blocked

```
Username: ' OR '1'='1
Password: anything
Expected: "Invalid username or password."  ← NOT a successful login
```

\---

## Skills \& Technologies Used

### Task 1 — Network Sniffer

|Skill / Tool|How it was used|
|-|-|
|Python|Core language|
|Scapy|Packet capture and layer analysis|
|colorama|Color-coded terminal output|
|netifaces|Cross-platform interface detection|
|CSV module|Structured log export|
|PCAP format|Wireshark-compatible binary capture|
|Network protocols|TCP, UDP, ICMP, ARP layer inspection|

### Task 2 — Phishing Awareness Training

|Skill / Tool|How it was used|
|-|-|
|pptxgenjs|Programmatic PowerPoint generation|
|react-icons|Font Awesome icons rendered as PNG|
|sharp|SVG-to-PNG icon conversion|
|Graphic design|Cherry Bold color palette, layout design|
|Security research|Case study research (Google, DNC, Twitter)|
|Instructional design|Quiz design, knowledge-check structure|

### Task 3 — Secure Coding Review

|Skill / Tool|How it was used|
|-|-|
|Python / Flask|Web application framework|
|SQLite|Database for user storage|
|bcrypt|Industry-standard password hashing|
|OWASP Top 10|Framework for vulnerability classification|
|Manual code review|Line-by-line security audit|
|HTTP security headers|Defense-in-depth browser protection|
|CSRF mitigation|Token generation and timing-safe comparison|
|Rate limiting|Per-IP login attempt tracking|

\---

## How to Run Everything

### Prerequisites

```bash
# Task 1
pip install scapy colorama

# Task 3
pip install flask bcrypt

# Task 2 — no install needed, just open the .pptx file
```

### Task 1 — Network Sniffer

```bash
cd Task1\_NetworkSniffer/

# Windows (Administrator)
python Task1\_Perfect.py

# Linux / macOS (requires sudo for raw socket access)
sudo python3 Task1\_Perfect.py

# Press Ctrl+C to stop — PCAP and logs saved automatically
```

### Task 2 — Phishing Training

```
Open Task2\_PhishingTraining/Task2\_Phishing\_Awareness\_Training.pptx
with PowerPoint, Google Slides, LibreOffice Impress, or Keynote
```

### Task 3 — Secure Flask App

```bash
cd Task3\_SecureCoding/
python Task3\_Perfect\_SecureCoding.py

# Open http://127.0.0.1:5000
# Login: admin / SecurePass@99
```

\---

## Key Learnings

### From Task 1 — Network Sniffer

Working with Scapy taught me how much of networking happens "below the surface" of normal computer use. Every browser request, DNS lookup, and ping generates multiple packets with distinct structures. The most surprising thing was how much useful information is visible in plaintext on unencrypted traffic — and how little of it most people are aware of.

The cross-platform challenge taught me that writing truly portable code requires deliberately testing assumptions. The original Windows-only code was a single import line — but it was enough to make the entire tool useless on Linux and macOS. Defense-in-depth applies to code quality, not just security.

### From Task 2 — Phishing Awareness

Researching the real-world case studies was the most valuable part of this task. Reading about the DNC spear phishing attack in detail revealed something counterintuitive: it wasn't a sophisticated exploit — it was a fake Google password-reset email. The sophistication was in the targeting and timing, not the technical payload. This reinforced that human factors are often the weakest link in any security system, and that awareness training is genuinely one of the highest-return security investments an organization can make.

The quiz design process also taught me how to frame security knowledge as practical skills rather than abstract facts. "What is a homograph attack?" is a poor quiz question. "Is `support@g00gle.com` a legitimate Google address?" tests the same knowledge in a way that has direct real-world application.

### From Task 3 — Secure Code Review

The secure coding task reinforced how easy it is to write vulnerable code and how expensive it is to fix later. The original vulnerable Flask app was about 20 lines. The secure version is over 500 lines — not because security is complicated in theory, but because doing it properly requires handling every edge case: What if the CSRF token is missing? What if the database errors out? What if the input is empty? What if the IP sends 1,000 requests?

The bcrypt exercise was particularly instructive. Most developers understand that "passwords should be hashed" but fewer understand *why* bcrypt specifically is the right choice — it is intentionally slow, which is exactly the opposite of what most engineering optimizes for. Understanding the threat model (offline cracking of a stolen database) clarifies why computational cost is a feature, not a bug.

\---

## 

