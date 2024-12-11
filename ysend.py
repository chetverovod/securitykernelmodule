from scapy.all import *

#ip=IP(dst='192.168.56.133', options=IPOption_Security(security=0x56))
#ip=IP(dst='192.168.56.134', options=IPOption_Security(security=0))
ip=IP(dst='192.168.56.134', options=IPOption_NOP() / IPOption_Security(security=0))
SYN=TCP(sport=1030, dport=9090, flags='S', seq=10) 
SYNACK=sr1(ip/SYN)
my_ack = SYNACK.seq + 1
ACK=TCP(sport=1030, dport=9090, flags='A', seq=11, ack=my_ack) 
send(ip/ACK)

payload = 'SEND TCP'
PUSH=TCP(sport=1030, dport=9090, flags='PA', seq=11, ack=my_ack) 
packet = ip/PUSH/payload
send(packet)
ls(packet)
