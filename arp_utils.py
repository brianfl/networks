import socket, subprocess, select
from struct import pack, unpack, calcsize


# finds our local IP address. Modified from StackOverflow.

def _find_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # issuing a connect call forces the socket to present an external IP, which we can retrieve

    s.connect(("1", 1))
    ip_address = s.getsockname()[0]
    s.close()
    ip_address = ip_address.split(".")

    return ip_address

# finding the name of the ethernet interface
def _find_eth_iface_name():

    eth_name = (
        str(subprocess.check_output(["ip", "route", "list", "0/0"]), 'utf-8')
        .partition("dev")[2]
        .partition("proto")[0]
        .strip()
    )

    return eth_name 

# finds MAC address in list form
def _find_mac():

    mac_folder = _find_eth_iface_name()
    
    mac_address = (
        str(subprocess.check_output(["cat", "/sys/class/net/" + mac_folder + '/address']), 'utf-8')
        .partition("\n")[0]
        .split(":")
    )

    return mac_address

# adds a MAC address (in list form) to a byte string
def _add_mac(mac, string):

    for entry in mac:
        decimal_val = int(entry, 16)
        string += pack('!B', decimal_val)

    return string


# adds an IP address (in list form) to a byte string
def _add_ip(ip, string):

    for entry in ip:
        entry = int(entry)
        string += pack("!B", entry)

    return string


# constructs an ARP packet to be sent to a specific target IP
def construct_arp_packet(target_ip):

    mac_address = _find_mac()
    ip_address = _find_ip()
    target_ip_list = target_ip.split(".")
    arp_packet = b''

    arp_packet += 6*pack('!B', 255) # destination address (broadcast MAC)
    arp_packet = _add_mac(mac_address, arp_packet) # source hardware address (our MAC)
    arp_packet += pack("!H", 2054) # frame type
    arp_packet += pack("!H", 1) # hardware type
    arp_packet += pack("!H", 2048) # protocol type
    arp_packet += pack("!B", 6) # hardware size
    arp_packet += pack("!B", 4) # protocol size
    arp_packet += pack("!H", 1) # opcode
    arp_packet = _add_mac(mac_address, arp_packet) # sender hardware address (our MAC)
    arp_packet = _add_ip(ip_address, arp_packet) # sender protocol address (our IP)
    arp_packet += 6*pack('!B', 0) # ignoring target HW address
    arp_packet = _add_ip(target_ip_list, arp_packet) # target IP

    return arp_packet

# send a request and receive a reply for an ARP packet
def send_receive_arp(packet, max_failures=3, timeout=.05):

    s = socket.socket(
        socket.AF_PACKET, 
        socket.SOCK_RAW, 
        socket.htons(0x0806) # htons swaps the endianness of the protocol number
    ) 

    s.bind((_find_eth_iface_name(), 0))
    s.send(packet)
    response = select.select([s], [], [], timeout)

    if response[0]:
        response = s.recvfrom(4096)[0]
        if response[28:32] == packet[38:42]: # checking that the IPs match
            s.close()
            return response

    s.close()
    max_failures -= 1

    if max_failures != 0:
        send_receive_arp(packet, max_failures=max_failures, timeout=timeout)
    else:
        return None

# decodes the MAC and IP address from an ARP packet
def mac_ip_decoder(packet):

    mac_packet = packet[6:12]
    decimal_mac = unpack("!6B", mac_packet)
    hex_mac_list = [hex(i) for i in decimal_mac]
    mac_address = ":".join([i[2:] for i in hex_mac_list])

    ip_packet = packet[28:32]
    decimal_ip = unpack("!4B", ip_packet)
    str_ip_list = [str(i) for i in decimal_ip]
    ip_address = ".".join(str_ip_list)

    return ip_address, mac_address
