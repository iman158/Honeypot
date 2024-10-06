# Honeypot
This script sets up a honeypot on honeypot_ip and honeypot_port that mimics the target service. When an attacker attempts to connect to the target port, the script sends a SYN/ACK packet to the attacker, indicating that the port is open. The script then logs the attacker's IP address, port, and the time of the attempt.
