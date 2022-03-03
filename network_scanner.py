from arp_utils import *

# finds netmasks (in slash notation)
def find_netmask():

    netmask = (
        str(subprocess.check_output(["ip", "route", "show"]), 'utf-8')
        .split("\n")[:-1][-1]
        .partition("dev")[0]
        .strip()
    )

    return netmask

# generates all possible IP addresses on a network given the netmask (in slash notation)
def generate_possible_ips(netmask):

    netmask = netmask.split("/")
    b_ip_string = ''

    for dec in netmask[0].split("."):

        b_ip_string += (str(bin(int(dec)))[2:]).zfill(8)
    
    binary_ip = bin(int(b_ip_string, 2))

    list_ips = []

    free_bits = (32-int(netmask[1]))
    num_addresses = 2**free_bits - 2
    
    for i in range(num_addresses):
    
        binary_ip = bin(
            int(binary_ip, 2) + int('1', 2)
        )

        decimal_ip = ".".join((
            str(int(binary_ip[2:10], 2)),
            str(int(binary_ip[10:18], 2)),
            str(int(binary_ip[18:26], 2)),
            str(int(binary_ip[26:34], 2))
        ))

        list_ips.append(decimal_ip)

    return list_ips
    

# given a list of addresses, scan all of them and return active ones
def network_arp_scan(ip_list):
    
    active = []

    for ip in ip_list:
        p = construct_arp_packet(ip)
        reply = send_receive_arp(p)

        if reply is not None:
            active.append(reply)
            print(ip, "Complete and active.")
        else:
            print(ip, "Complete.")
    
    return active
    


if __name__ == "__main__":
    
    netmask = find_netmask()
    possible_addresses = generate_possible_ips(netmask)
    active_hosts = network_arp_scan(possible_addresses)

    for host in active_hosts:
        print(host[0], "-", host[1])



