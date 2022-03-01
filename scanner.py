import socket, subprocess
from struct import pack

dest_ip = '192.168.1.101'


# finds our local IP address. Modified from StackOverflow. How does this work?
# connection doesn't succeed (obviously), but connecting changes our address. How?
def _find_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1", 1))
    ip_address = s.getsockname()[0]
    s.close()
    ip_address = ip_address.split(".")

    return ip_address


# finding our MAC address from the terminal - this restricts this program to just Linux
# returns MAC in list form
def _find_mac():

    mac_folder = (
        str(subprocess.check_output(["ip", "route", "list", "0/0"]), 'utf-8')
        .partition("dev")[2]
        .partition("proto")[0]
        .strip()
    )

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

    arp_packet += 6*pack('!B', 255) # adding the destination address, which is the broadcast MAC
    arp_packet = _add_mac(mac_address, arp_packet) # source hardware address (our MAC)
    arp_packet += pack("!H", 2054) # frame type
    arp_packet += pack("!H", 1) # hardware type
    arp_packet += pack("!H", 2048) # protocol type
    arp_packet += pack("!B", 6) # hardware size
    arp_packet += pack("!B", 4) # protocol size
    arp_packet += pack("!H", 1) # opcode
    arp_packet = _add_mac(mac_address, arp_packet) # sender hardware address (our MAC again)
    arp_packet = _add_ip(ip_address, arp_packet) # sender protocol address (our IP)
    arp_packet += 6*pack('!B', 0) # ignoring target HW address because this is a request
    arp_packet = _add_ip(target_ip_list, arp_packet) # target IP

    return arp_packet


# send a packet over a raw socket
def send_raw_packet(packet):

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth1", 0)) # no such device.
    s.send(packet)
    s.close()

p = construct_arp_packet(dest_ip)
send_raw_packet(p)

