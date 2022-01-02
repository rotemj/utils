# This is a sample Python script.


# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import sys


# Press the green button in the gutter to run the script.
import os
import sys
import scapy.layers.l2
import json
import re
import scapy.sendrecv
import scapy.packet
import scapy.layers.inet
import scapy.utils
from scapy.all import *
#from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.inet6 import IP, UDP, Ether, IPv6
from scapy.utils import PcapWriter
import ipaddress
from ipaddress import ip_address, IPv4Address




def prepare_packet(time, protocol, sport, dport, sip, dip, size):
    try:
        payload = Raw('0' * size)
        if protocol == "tcp":
            tcp_udp_layer = TCP(sport=sport, dport=dport)
        else:
            tcp_udp_layer = UDP(sport=sport, dport=dport)

        ether_layer = Ether(src="ab:cd:ef:ab:cd:ef", dst="ff:ff:ff:ff:ff:ff")
        ip_layer = None
        if type(ip_address(sip)) is IPv4Address:
            ip_layer = IP(src=sip, dst=dip)
        else:
            ip_layer = IPv6(src=sip, dst=dip)

        pkt = ether_layer / ip_layer / tcp_udp_layer / payload
        pkt.time = time
        pktdump.write(pkt=pkt)

    except Exception:
        print ("{} {}", sip, dip)
# wrpcap(filename="~/Download/banana.pcap", packet=pkt, append=True)
  #  wrpcap("banana.pcap", pkt)


    #packets.append(packet_)


if __name__ == '__main__':
    try:

        if os.path.exists('banana.pcap'):
            os.remove('banana.pcap')
        pktdump = PcapWriter("banana.pcap", append=True, sync=True)
        file_name = sys.argv[1]
        f = open(file_name, "r")
        packets = []
        time = 0
        for line in f:
            packet_json = re.search("Periodic stats: ({.*}$)", line)
            if packet_json is not None:
                time += 2  # two seconds
                details = packet_json.group(1)
                j = json.loads(details)
                for connection in j["connections"]:
                    protocol = connection["protocol"]

                    src_conn = connection["src"]
                    src_bytes = src_conn["bytes"]
                    src_ip = src_conn["ip"]
                    src_port = src_conn["port"]
                    src_packets = src_conn["packets"]
                #    if src_bytes < 0 or src_bytes > 65535:
                 #       print "src_bytes:{}", src_bytes

                    dst_conn = connection["dst"]
                    dst_bytes = dst_conn["bytes"]
                    dst_ip = dst_conn["ip"]
                    dst_port = dst_conn["port"]
                    dst_packets = dst_conn["packets"]
                #    if dst_bytes < 0 or dst_bytes > 65535:
                #        print "dst_bytes:{}", dst_bytes

    ######################################################################################
                    if src_packets == 0:
                        continue

                    src_packet_size = (src_bytes - (40 * src_packets)) / src_packets #payload size
                    last_packet_size = (src_bytes - (40 * src_packets)) % src_packets #remainder payload size
                    if last_packet_size == 0:
                        last_packet_size = src_packet_size

                    for i in range(src_packets):
                        if i == 0:
                            packet_size = last_packet_size
                        else:
                            packet_size = src_packet_size

                        prepare_packet(time, protocol, src_port, dst_port, src_ip, dst_ip, packet_size)


    ######################################################################################3

                    if dst_packets == 0:
                        continue

                    dst_packet_size = (dst_bytes - (40 * dst_packets)) / dst_packets
                    last_packet_size = (dst_bytes - (40 * dst_packets)) % dst_packets
                    if last_packet_size == 0:
                        last_packet_size = dst_packet_size

                    for i in range(dst_packets):
                        if i == 0:
                            packet_size = last_packet_size
                        else:
                            packet_size = dst_packet_size

                        prepare_packet(time, protocol, dst_port, src_port, dst_ip, src_ip, packet_size)





      #  wrpcap("filtered.pcap", packets)
    except Exception:
        print ("exception")



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
