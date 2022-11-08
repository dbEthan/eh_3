import sys
import scapy.all as scapy
from scapy.layers.inet import IP, TCP

# Host discovery
# Source: https://www.geeksforgeeks.org/network-scanning-using-scapy-module-python/
def arp_discovery(ip_range):
    active_ips = []
    for ip in ip_range:
        request = scapy.ARP()
        request.pdst = ip
        broadcast = scapy.Ether()
        broadcast.dst = 'ff:ff:ff:ff:ff:ff'

        request_broadcast = broadcast / request
        clients = scapy.srp(request_broadcast, timeout=1)[0]
        log_file = open("./logging.txt", "a")
        for element in clients:
            ip_address = element[1].psrc
            mac_address = element[1].hwsrc
            print(ip_address + "      " + mac_address)
            log_file.write(ip_address + "      " + mac_address + "\n")
            active_ips.append(ip_address)
        log_file.close()
    return active_ips


# Service discovery
# Source: https://stackoverflow.com/questions/71400051/scapy-port-scanner
def port_scanner(ip_addresses, start_port=1, end_port=1000):
    log_file = open("./logging.txt", "a")
    for ip in ip_addresses:
        for x in range(start_port, end_port):
            packet = IP(dst=ip) / TCP(dport=x, flags='S')
            response = scapy.sr1(packet, timeout=0.5, verbose=0)
            if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                log_file.write(f'Port {str(x)} is open!\n')
                print(f'Port {str(x)} is open!\n')
                scapy.sr(IP(dst=ip) / TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=0)
    log_file.close()


# OS detection
# Source: https://security.stackexchange.com/questions/142382/understanding-remote-os-detection-using-scapy
def os_detection(dest_ip):
    for ip in dest_ip:
        seq = 12345
        sport = 1040
        dport = 80

        ip_packet = IP(dst=ip)
        syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)

        packet = ip_packet / syn_packet
        synack_response = scapy.sr1(packet)

        next_seq = seq + 1
        my_ack = synack_response.seq + 1

        ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)

        scapy.send(ip_packet / ack_packet)

        payload_packet = TCP(sport=sport, dport=dport, flags='', seq=next_seq)
        payload = "this is a test"
        scapy.send(ip_packet / payload_packet / payload)


# PCAP analysis
# Source: https://stackoverflow.com/questions/10800380/scapy-and-rdpcap-function
def packet_analysis(path_pcap):
    scapy.rdpcap(path_pcap)
    packet = scapy.sniff(offline=path_pcap)
    packet.show()


def main():
    log_file = open("./logging.txt", "a")
    log_file.close()
    if len(sys.argv) > 2:
        if sys.argv[1] == "-arp":
            ip_addresses = sys.argv[2][1:-1]
            ip_addresses = ip_addresses.split(", ")
            arp_discovery(ip_addresses)
        elif sys.argv[1] == "-port":
            ip_addresses = sys.argv[2][1:-1]
            ip_addresses = ip_addresses.split(", ")
            if len(sys.argv) > 3:
                start = sys.argv[3]
                end = sys.argv[4]
                port_scanner(ip_addresses, start, end)
            else:
                port_scanner(ip_addresses)
        elif sys.argv[1] == "-os":
            ip_addresses = sys.argv[2][1:-1]
            ip_addresses = ip_addresses.split(", ")
            os_detection(ip_addresses)
        elif sys.argv[1] == "-packet":
            packet_path = sys.argv[2]
            packet_analysis(packet_path)
        else:
            print(
                "python main.py <-arp|-packet|-os|-port> <ip_addresses|packet_path|ip_addresses|<ip_adresses and startport|endport>>")

    else:
        print(
            "python main.py <-arp|-packet|-os|-port> <ip_addresses|packet_path|ip_addresses|"
            "<ip_adresses and startport|endport>>")

    
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
