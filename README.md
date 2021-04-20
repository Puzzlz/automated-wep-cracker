# COMP4203 - Project
This code utilizes the aircrack suite to sniff packets, inject packets, actively attack a WEP network, and crack the password for that network.

## Requirements
The following needs to be installed:
`sudo apt-get install aircrack-ng`

## Setup
Before the program can be run, there needs to be a WEP network to run it on. This will most likely require older hardware as more modern ones have this encryption method disabled.

The code also needs to be run from a Linux device, since Windows devices cannot easily be put into monitor mode (required for injecting and sniffing packets not destined for it).

To find your network interface card name, run: `ip link show`

Run the following to put it into monitor mode:
```
sudo airmon-ng check kill
sudo airmon-ng start <wireless_iface>
```

## Running
The following command will run the program from start to finish:
`sudo python3 mp_wep_attacker.py -i <iface> -a <access_point_mac> -s <mac_of_attack_device> -c <channel> -r <IV target>`

The following command will run the program without aircrack, but save the output files to be run on later:
`sudo python3 automated_mp_wep_attacker.py -i <iface> -a <access_point_mac> -s <mac_of_attack_device> -c <channel> -r <IV target>`

## Information
### Arguments
```
"-i", "--interface", help="interface to sniff and send packets from", required=True)
"-a", "--access_point", help="MAC address of the access point, also known as the BSSID of the network.", required=True)
"-s", "--source", help="MAC address of the device injecting the packets. run ifconfig to find it", required=True)
"-c", "--channel", help="Channel that target network is operation on.", required=True)
"-r", "--captured_arp_packets", help="Number of IVs to capture before attempting to crack password.", required=True)
"-p", "--packets", help="packets per second to inject", default=500)
"-t", "--target", help="MAC address of the target device for the de-auth attack, default is broadcast", default='ff:ff:ff:ff:ff:ff')
"-n", "--number_deauth", help="Number of de-auth packets to send per batch", default=25)
```

### Gathering data
`sudo airodump-ng <iface>`