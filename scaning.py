import nmap
import python_arptable

map_mac = []


class Host:
	mac_address= ''
	IP_address = ''
	status = ''

	def __init__(self):
		self.mac_address= ''
		self.IP_address = ''
		self.status = ''

	def __str__(self):
		return("mac : "+self.mac_address+"\nIP : "+self.IP_address+"\nstatus : "+self.status)
		
	def setMAC(self, mac):
		self.mac_address = mac
	def setIP(self, IP):
		self.IP_address = IP
	def setStatus(self, status):
		self.status = status
	def getMAC(self):
		print(self.mac_address)
		return self.mac_address
	def getIP(self):
		return self.IP_address
	def getStatus(self):
		return self.status 
	


def scan_ping(target):
	print("scanning...")
	nm = nmap.PortScanner()
	nm.scan(hosts=target, arguments='-sn')
	new_hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
	#for host, status in new_hosts_list:
    #		print(str(host)+":"+str(status))
	return new_hosts_list
	

def get_mac_address():
	print("importing arp table")
	from python_arptable import ARPTABLE
	#print(ARPTABLE)
	mac=[(ARPTABLE[x]['HW address'],ARPTABLE[x]['IP address']) for x in range(0, len(ARPTABLE))]
	#print(mac)
	return mac

def add_new_mac():	
	lenmap = len(map_mac)
	newmac = get_mac_address()
	lenmac = len(newmac)
	for x in map_mac:
		i = 0
		for y in newmac:
			if y[0]=="00:00:00:00:00:00" :
				print(y[0]+" : non pris en compte ")
			elif x.getMAC() == y[0] or y[0]=="00:00:00:00:00:00":
				del newmac[i]				
			i+=1	
	if newmac != []:
		print("New MAC address detected : "+ str(newmac))	
		for y in newmac:
			host= Host()
			host.setMAC(y[0])
			host.setIP(y[1])
			map_mac.append(host)
			
	#map_mac.extend(newmac)
	del newmac[:]
	#print(str(map_mac))


def sync(new_hosts_list):
	print("syncing...")
#	print(new_hosts_list)
	for mapped_host in map_mac:
		#print("mapped_host "+str(mapped_host))
		iscon = sum(x.count(mapped_host.getIP()) for x in new_hosts_list)
		#print("isdeconnected = "+ str(iscon))		
		if iscon > 0 :
			print("Si dans mapped host et pas dans new host alors IP deconnecte : "+ str(mapped_host.getMAC()))
			mapped_host.setStatus('down')
		
		for host, status in new_hosts_list:
			#print("host :: "+host)
			#print("status :: "+status)
			if mapped_host.getIP() == host:
						if mapped_host.getStatus() != status:
							mapped_host.setStatus(status)
				

def show_mapping():
	for host in map_mac:
		print(str(host))
	

nh = scan_ping('192.168.0.0'+'/'+'24')
add_new_mac()
print("----------------------------------------------------------------------------------")
add_new_mac()
sync(nh)
show_mapping()
	
#A ce stade : fusionner pour faire la map [MAC IP up/down] - fonction sync? en meme tEMPS QUE ADD new mac ---probleme avec 00:00:00:00:00:00


"""
pkts=sniff(count=3,filter="arp")
pkts.summary()

i=0
for x in pkts:
	
	print("printing pkts["+str(i)+"].show()")
	x.show()
	i+= 1
"""


