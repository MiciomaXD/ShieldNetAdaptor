import scapy.all as sc
from config import *

def main() -> int:

    a=None
    try:
        print ('[+] Reading and parsing pcap file', PCAP_PATH)
        a=sc.sniff(offline=PCAP_PATH, count=200)
        #a = sc.rdpcap(PCAP_PATH)

    except Exception as e:
        print ('[!] Cannot open/read pcap file.' \
          '\n\nThe error message is:', e)
        exit(1)

    print(a.show())
    sessions = a.sessions()

    for k,v in sessions.items():
        print(k,v)

    return 0

if __name__ == '__main__':
    main()