# 🛡️ TCP Honeypot with Live GeoIP Dashboard

A **low-interaction honeypot** built with **Python and Scapy** that detects and logs TCP SYN attacks, performs **real-time GeoIP lookups**, and visualizes attacks in a **live Matplotlib dashboard**.

---

## Features

- 🕵️‍♂️ **TCP SYN Detection**: Captures incoming connection attempts on specified ports.  
- 🌍 **GeoIP Lookup**: Resolves attacker IPs to country and city in real-time with caching.  
- 📊 **Live Dashboard**: Visualizes top attacker countries, attack frequency, and targeted ports.  
- 💾 **CSV Logging**: All attacker details are stored for offline analysis.  
- ⚡ **Multi-threaded**: Sniffer runs in background while dashboard updates live.  
- 🔒 **Safe for testing**: Low-interaction honeypot; mimics services without running them.  

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/username/honeypot-dashboard.git
cd honeypot-dashboard
pip install -r requirements.txt
