from scapy.all import *
import csv
import requests
import time
import threading
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP


from collections import defaultdict

# ----------------------------
# Config
# ----------------------------
target_ip = "192.168.1.100"
target_port = 80
honeypot_ip = "192.168.1.101"
honeypot_port = 80
csv_file = "honeypot_logs.csv"
geoip_cache = {}  # cache dictionary for storing IP -> GeoIP lookups

# ----------------------------
# GeoIP lookup with caching
# ----------------------------
def get_geoip(ip):
    if ip in geoip_cache:
        return geoip_cache[ip]  # return from cache if available
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        if response['status'] == 'success':
            geo_data = {
                'country': response.get('country', 'Unknown'),
                'city': response.get('city', 'Unknown'),
                'lat': response.get('lat', 0.0),
                'lon': response.get('lon', 0.0)
            }
        else:
            geo_data = {'country': 'Unknown', 'city': 'Unknown', 'lat': 0.0, 'lon': 0.0}
    except:
        geo_data = {'country': 'Error', 'city': 'Error', 'lat': 0.0, 'lon': 0.0}

    geoip_cache[ip] = geo_data  # store in cache
    return geo_data

# ----------------------------
# Packet handler
# ----------------------------
def handle_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # TCP SYN
        attacker_ip = packet[IP].src
        attacker_port = packet[TCP].sport
        attack_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))

        # Respond with SYN/ACK
        ack_packet = IP(src=honeypot_ip, dst=attacker_ip) / TCP(
            sport=honeypot_port, dport=attacker_port,
            flags='SA', seq=packet[TCP].seq, ack=packet[TCP].seq+1
        )
        send(ack_packet, verbose=False)

        # GeoIP Lookup with caching
        geo = get_geoip(attacker_ip)

        # Log to CSV
        with open(csv_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([attacker_ip, attacker_port, attack_time, geo['country'], geo['city']])

        print(f"[+] Attack from {attacker_ip}:{attacker_port} at {attack_time} "
              f"({geo['country']} - {geo['city']})")

# ----------------------------
# Sniffer thread
# ----------------------------
def start_sniffer():
    sniff(filter=f"tcp and dst port {target_port}", prn=handle_packet)

# ----------------------------
# Dashboard
# ----------------------------
def animate(i):
    try:
        df = pd.read_csv(csv_file, names=["IP", "Port", "Time", "Country", "City"])
        df = df.tail(100)  # keep last 100 entries

        plt.cla()
        country_counts = df["Country"].value_counts()
        country_counts.plot(kind='bar', ax=plt.gca())
        plt.title("Top Attack Sources by Country")
        plt.ylabel("Count")
        plt.xlabel("Country")
    except Exception as e:
        print(f"Dashboard error: {e}")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    # Ensure CSV has a header if empty
    try:
        with open(csv_file, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Port", "Time", "Country", "City"])
    except FileExistsError:
        pass

    # Start packet sniffer in background
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # Start live dashboard
    fig = plt.figure()
    ani = FuncAnimation(fig, animate, interval=3000)
    plt.show()
