import scapy.all as sc

def f():
    for packet in sc.sniff(offline='\\test.pcap', count=5):
        print(packet)

f