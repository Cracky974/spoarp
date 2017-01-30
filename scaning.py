import nmap
import python_arptable

map_mac = []
newmac = []

def scan_ping(target):
	nm = nmap.PortScanner()
	nm.scan(hosts=target, arguments='-sn')
	new_hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
	print new_hosts_list
	for host, status in new_hosts_list:
    		print(str(host)+":"+str(status))
	

def get_mac_address():
	from python_arptable import ARPTABLE
	#print(ARPTABLE)
	mac=[(ARPTABLE[x]['HW address'],ARPTABLE[x]['IP address']) for x in range(0, len(ARPTABLE))]
	#print(mac)
	return mac

def add_new_mac():
	
	lenmap = len(map_mac)
	newmac = filter(lambda a: a != '00:00:00:00:00:00',get_mac_address() )
	lenmac = len(newmac)
	for x in range(0, lenmap):
		i=0
		for y in newmac:
			if map_mac[x] == y:
				del newmac[i]
			i+=1	
	map_mac.extend(newmac)
	print(map_mac)

scan_ping('192.168.0.0'+'/'+'24')
add_new_mac()
print("-----------------------------------")
add_new_mac()

#A ce stade : fusionner pour faire la map [MAC IP up/down] - fonction sync? en meme temps que new mac?

"""
pkts=sniff(count=3,filter="arp")
pkts.summary()

i=0
for x in pkts:
	
	print("printing pkts["+str(i)+"].show()")
	x.show()
	i+= 1
"""


