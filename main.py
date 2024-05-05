from scapy.all import ARP, Ether, srp
import argparse

def scan_network(target_ip):
#==============================================================================================================================
         #Create an Ethernet and ARP packet to broadcast + Send packet & capture returned packets with
#==============================================================================================================================
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=target_ip)
    packet = broadcast / arp_request

    result = srp(packet, timeout=10, verbose=False)[0]

    # List 
    devices = []

    for sent, received in result:
   #==============================================================================================================================
        # For each response, append IP and MAC address to `devices` list
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    parser = argparse.ArgumentParser(description='Simple ARP-based network scanner.')
    parser.add_argument('target', type=str, help='Target IP range to scan, e.g., 192.168.1.1/24')
    args = parser.parse_args()

    target_ip = args.target
    devices = scan_network(target_ip)

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

if __name__ == "__main__":
    main()
