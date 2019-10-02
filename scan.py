"""
    Script for network scans/port scans. Needs to run in sudo.
"""

from scapy.all import ARP, Ether, srp, RandShort, sr1
from scapy.layers.inet import IP, UDP, TCP, ICMP
from manuf import manuf
from tqdm import tqdm

import ipaddress
import argparse
import time
import json

'''
    Broadcast `ff:ff:ff:ff:ff:ff` asks each host on a network who has the target ip address, the 
    host with the IP address will respond saying they have the ip address.
'''


def lan_scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Mac broadcast packet.
    packet = ether / arp
    result = srp(packet, timeout=0.5, verbose=0)[0]
    return [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]


def display_lan(devices, ports=None):
    print("\n\nResults:")
    p = manuf.MacParser(update=True)
    for entry in devices:
        vendor = p.get_manuf(entry['mac'])
        vendor = "Unknown" if vendor is None else vendor
        print("\nIP: " + entry['ip'] + "\nMac: " + entry['mac'] + "\nVendor: " + vendor)

        if ports is not None:
            if entry['ip'] in ports:
                print("Open ports: " + str(ports[entry['ip']]))
            else:
                print("No Open Ports.")

'''
    Prints output to html file.
'''


def display_lan_html(filename, devices, ports=None):
    with open(filename, 'w') as f:
        f.write("<!DOCTYPE html>")
        f.write("<html><head><h1>Results:</h1></head><body>")

        p = manuf.MacParser(update=True)
        for entry in devices:
            vendor = p.get_manuf(entry['mac'])
            vendor = "Unknown" if vendor is None else vendor
            f.write("<br><b>IP: " + entry['ip'] + "</b><br>Mac: " + entry['mac'] + "<br>Vendor: " + vendor)

            if ports is not None:
                if entry['ip'] in ports:
                    f.write("<br>Open ports: " + str(ports[entry['ip']]))
                else:
                    f.write("<br>No Open Ports.")

        f.write('</body></html>')


'''
    TCP stealth scan. 
     
        ----------------------------------
        |   Open Port    |  Closed Port  |
        |----------------|---------------|    The stealth scan does not send RST+ACK and
        |    SYN+PORT    |   SYN+PORT    |    the end so the handshake is not initialized.
        |  ----------->  |  -----------> |
        |     SYN+ACK    |      RST      |
        |  <-----------  |  <----------  |
        |       RST      |               |
        |  ----------->  |               |
        ----------------------------------
'''


def tcp_port_scan(ip_range, ports):
    port_scan = {}
    if type(ip_range) != list:
        ip_range = ipaddress.IPv4Network(ip_range)

    loop = tqdm(total=len(list(ip_range)), position=0, leave=False)
    for ip in ip_range:
        ip = str(ip)
        loop.update(1)
        loop.set_description('Scanning: {}'.format(ip))
        for port in ports:
            syn_packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags='S')
            resp = sr1(syn_packet, timeout=0.5, verbose=0)
            if resp is not None:
                if resp.haslayer(TCP):
                    if resp.getlayer(TCP).flags == 0x12:  # SYN_ACK means port is open over TCP.
                        if ip in port_scan:
                            port_scan[ip].append(port)
                        else:
                            port_scan[ip] = list()
                            port_scan[ip].append(port)

                        sr1(IP(dst=ip) / TCP(dport=port, flags='R'), timeout=0.5, verbose=0)

    return port_scan


'''
    UDP scan. 

        --------------------------------------------------------------------
        |   Open Port    |  Closed Port  | Filtered Port  | Open/Filtered  |
        |----------------|---------------|----------------|----------------|    
        | udpPacket+PORT | udpPacket+PORT| udpPacket+PORT | udpPacket+PORT |
        | -------------> | ------------> | -------------> | -------------> |
        |    udpPacket   |ICMP Type3Code3|ICMP 1,2,9,10,13|   No response  |
        |  <-----------  | <------------ | <------------- | <------------- |
        --------------------------------------------------------------------
'''


def udp_port_scan(ip_range, ports):
    port_scan = {}
    if type(ip_range) != list:
        ip_range = ipaddress.IPv4Network(ip_range)

    loop = tqdm(total=len(list(ip_range)), position=0, leave=False)
    for ip in ip_range:
        loop.update(1)
        loop.set_description('Scanning: {}'.format(ip))
        for port in ports:

            def addData(ip_addr, port_num):
                if ip_addr in port_scan:
                    port_scan[ip_addr].append(port_num)
                else:
                    port_scan[ip_addr] = list()
                    port_scan[ip_addr].append(port_num)

            def transmit(dst_ip, dst_port):

                ans = sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=3, verbose=0)
                time.sleep(1)
                if ans is None:
                    # Open/Filtered
                    addData(dst_ip, dst_port)
                elif ans.has_layer(UDP):
                    # Open
                    addData(dst_ip, dst_port)
                elif ans.has_layer(ICMP):
                    if int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) == 3:
                        # Closed. Ignore.
                        pass
                elif int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    # Filtered, treating as closed so will ignore for now.
                    pass

            transmit(ip, port)

    return port_scan


'''
    Converts input ports from 80 443-445 to 80 443 444 445.
'''


def port_parser(ports):
    new_ports = []

    if ports is None:
        return []
    try:
        for port in ports:
            if '-' in port:
                parts = port.split('-')
                if type(parts[0]) == str:
                    parts[0] = int(parts[0])
                if type(parts[1]) == str:
                    parts[1] = int(parts[1])
                for i in range(parts[0], parts[1] + 1):
                    new_ports.append(i)
            else:
                if type(port) == str:
                    port = int(port)
                new_ports.append(port)
    except:
        raise ValueError("Ports were not in the correct format")

    return new_ports


'''
    Creates sample config file.
'''


def generate(name):
    with open(name, "w") as f:
        ips = ["192.168.0.1", "192.168.0.2", "192.168.0.3"]
        ports = ["22", "25", "53", "80", "443-445"]
        f.write(json.dumps({'ips': ips, 'ports': ports}, indent=2, sort_keys=True))


def parse_file(name):
    with open(name, "r") as f:
        data = json.loads(f.read())
    return data['ips'], port_parser(data["ports"])


def main():
    # Parse command line arguments.
    parser = argparse.ArgumentParser(description='LAN and Port Scanner')
    parser.add_argument('-ip', '--IP', help='What IP\'s to scan. EXP: 192.168.1.1 or 192.168.0.0/24')
    parser.add_argument('-p', '--port', nargs='+', help='Which ports to scan. EXP: 22 80 443-445')
    parser.add_argument('-f', '--file', help='File to read ips/ports from.')
    parser.add_argument('-g', '--generate', help='Generate sample config file, Provide name of sample config file.')
    parser.add_argument('-o', '--outputFile', help='Name of HTML output file to print results.')
    parser.add_argument('-m', '--mode', choices=['scan', 'scan-tcp', 'scan-udp'], default='tcp',
                        help='Scan - Do a lan scan. scan-tcp - Scan for TCP, scan-udp - scan for UDP')
    args = parser.parse_args()

    if args.generate is not None:
        generate(args.generate)
        exit(0)
    elif args.file is not None:
        ips, ports = parse_file(args.file)
    else:
        ips = args.IP
        if args.mode != 'trace' or args.mode != 'scan':
            ports = port_parser(args.port)

    print("Scanning: " + ips)
    if args.mode == 'scan':
        devices = lan_scan(ips)
        if args.outputFile:
            display_lan_html(args.outputFile, devices)
        else:
            display_lan(devices)
    elif args.mode == 'tcp':
        print("Checking if the following ports are open. " + str(ports))
        response = tcp_port_scan(ips, ports)
        print(response)
    elif args.mode == 'udp':
        print("Checking if the following ports are open. " + str(ports))
        response = udp_port_scan(ips, ports)
        print(response)
    elif args.mode == 'scan-tcp':
        print("Checking if the following ports are open. " + str(ports))
        devices = lan_scan(ips)
        online_clients = [entry['ip'] for entry in devices]
        response = tcp_port_scan(online_clients, ports)
        if args.outputFile:
            display_lan_html(args.outputFile, devices, response)
        else:
            display_lan(devices, response)
    elif args.mode == 'scan-udp':
        print("Checking if the following ports are open. " + str(ports))
        devices = lan_scan(ips)
        online_clients = [entry['ip'] for entry in devices]
        response = udp_port_scan(online_clients, ports)
        if args.outputFile:
            display_lan_html(args.outputFile, devices, response)
        else:
            display_lan(devices, response)


if __name__ == "__main__":
    main()
