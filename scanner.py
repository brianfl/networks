import socket, subprocess
from struct import pack

dest_ip = '192.168.1.101'

# client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

# server.bind(('enp0s31f6', 0))

def construct_packet(target_ip, htype=1, ptype=2048, plen=4, hlen=6, op=1):

    arp_packet = b''
    arp_packet += 6*pack('!B', 255)

    mac_folder = subprocess.check_output(["ls", "/sys/class/net/"], encoding='UTF-8').split("\n")[0]
    mac_address = subprocess.check_output(["cat", "/sys/class/net/" + mac_folder + '/address'], encoding='UTF-8')

    mac_address = mac_address[0:-1]

    print(pack('!6p', *[int(h, 16) for h in mac_address.split(":") ]))
    for num in mac_address.split(":"):
        dec_val = int(num, 16)
        print(dec_val)

        arp_packet += pack('!p', dec_val)
    return arp_packet

    spa = my_ip
    sha = my_mac

print(construct_packet(dest_ip))

