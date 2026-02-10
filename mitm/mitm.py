from scapy.all import sniff, TCP, Raw, IP


def packet_handler(pkt):
    #Only handle IP/TCP packets that also contain raw payload
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        tcp = pkt[TCP]
        #Only look at MySQL traffic (port 3306)
        if tcp.sport == 3306 or tcp.dport == 3306:
            data = bytes(pkt[Raw].load)
            #Print payload as ASCII, non-printables become '.'
            text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
            print(text)

#Sniff MySQL TCP packets on the Docker bridge interface
sniff(iface="br-66cdefd2e216", filter="tcp port 3306", prn=packet_handler, store=False)
