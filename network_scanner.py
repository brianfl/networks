from arp_utils import *

def find_netmask():


# generates all possible IP addresses on a network given the netmask
def generate_possible_ips(netmask):

    

# given a list of addresses, scan all of them and return active ones
def network_arp_scan(ip_list):

if __name__ == "__main__":
    
    netmask = find_netmask()
    possible_addresses = generate_possible_ips(netmask)
    active_hosts = network_arp_scan(possible_addresses)

    for host in active_hosts:
        print(host[0], "-", host[1])



