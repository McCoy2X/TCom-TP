from scapy.all import *
import math
import csv
import time
totalTime = 10000

def monitor_callback(pkt):
    curTime = time.time()
    with open('resultados/dc_s1.csv', 'ab') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow([str(curTime)] + [str(pkt.type)] + [str(pkt.dst)] + [str(pkt.src)])
    
    if ARP in pkt:
        with open('resultados/dc_s2.csv','ab') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow([str(pkt[ARP].op)] + [str(pkt[ARP].hwsrc)] + [str(pkt[ARP].hwdst)] + [str(pkt[ARP].psrc)] + [str(pkt[ARP].pdst)] + [str(pkt[Ether].dst)] + [str(pkt[Ether].src)] + [str(curTime)])

    
if __name__ == '__main__':
    sniff(prn=monitor_callback, store=0, timeout=1800)