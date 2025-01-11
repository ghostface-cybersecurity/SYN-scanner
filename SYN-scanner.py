from scapy.all import IP, TCP, sr1, ICMP 
import sys

def icmp_probe(ip):
    icmp_pack = IP(dst=ip)/ICMP()
    resp_packet = sr1(icmp_pack,timeout=10)
    return resp_packet != None

def syn_scan(ip, port):
    syn_packet = IP(dst = ip) / TCP(dport = int(port), flags = 'S') # create SYN-packet
    response_pack = sr1(syn_packet) # send the package and get the results

    if response_pack == None: # if it is empty
        print(f'No response from {ip} : {port}')
        return None
    
    if response_pack.getlayer(TCP).flags == 0x12: # check for the presence of SYN and ACK packets
        print(f'Port {ip} : {port} is open')
        return response_pack
    else:
        print('No SYN and ACK pakets')
        return None

if __name__ == '__main__':
    ip = sys.argv[1]
    port = sys.argv[2]
    if icmp_probe(ip):
        syn_ack_pack = syn_scan(ip, port)
        if syn_ack_pack == None:
            print('No SYN and ACK packets')
        else:
            syn_ack_pack.show()
    else:
        print('ICMP probe failed\nResult: None\n')
