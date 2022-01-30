from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from hashlib import sha1
from binascii import hexlify

# bad sha1 body digests
fd = open("bad.txt", "r")
bad_body_digests = [digest.strip() for digest in fd.readlines()]
fd.close()
#print(bad_body_digests)

# good sha1 body digests
fd = open("good.txt", "r")
good_body_digests = [digest.strip() for digest in fd.readlines()]
fd.close()
#print(good_body_digests)

# bloked ips
fd = open("blocked_ip.txt", "r")
blocked_ip = [digest.strip() for digest in fd.readlines()]
fd.close()
#print(blocked_ip)


# reading wireshark and other pcap samples
pkts = rdpcap('simple_http_get.cap') + rdpcap('large_post.trace') + rdpcap('sample.pcap')

digests = []
for pkt in pkts[TCP]:
    if (pkt.haslayer(HTTPRequest)):
        # it's source address blocked? 
        if (pkt[IP].src in blocked_ip):
            print("ALERT: " + pkt[IP].src + " should not made this request!\nReview the flow to understand how this source address pass firewall.")
        # it's this request recognized by threat intelligence as malicious???
        if (pkt[HTTPRequest].Method.decode() == "POST" and pkt.haslayer(Raw)):
            digest = hexlify(sha1(pkt[Raw].load).digest()).decode()
            if (digest in bad_body_digests):
                print("DANGEROUS: " + pkt[IP].src + " tried to inject an know malicous request")
            elif (digest in good_body_digests):
                continue
            else:
                digests.append(digest)

# append unknow digests
fd2 = open("unknown.txt", "r")
fd = open("unknown.txt", "a")
lines = [line.strip() for line in fd2.readlines()]
for dgt in digests:
    if (dgt not in lines):
        fd.write("\n")
        fd.write(dgt)
fd.close()
fd2.close()