import sys
import socket
import getopt
import threading
import subprocess
import nmap
from scapy.all import *

#global
nm = nmap.PortScanner()
nm.scan(hosts='192.168.0.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
     print(str(host)+":"+str(status))

"""
pkts=sniff(count=3,filter="arp")
pkts.summary()

i=0
for x in pkts:
	
	print("printing pkts["+str(i)+"].show()")
	x.show()
	i+= 1
"""

def usage():
    print "spoarp\n"
    
    print "Usage: spoarp.py -t target_network -m mask "
    #print "-l --listen                - listen on [host]:[port] for incomming connection"
    print
    print "Examples:"
    print "spoarp.py -t 192.168.0.0 -m 24"
    sys.exit(0)





def main():
    global target
    
    if not len(sys.argv[1:]): usage()
    
    #read command options
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu",["help","target","mask"])
    except getopt.GetoptError as err:
        print str(err)
        #usage()
    
    for o,a in opts:
        if o in ("-h" or "--help"):
            usage()
        elif o in ("-l" or "--listen"):
            listen = True
        elif o in ("-e" or "--execute"):
            execute = a
        elif o in ("-c" or "--command"):
            command=True
        elif o in ("-u" or "--upload"):
            upload_destination=a
        elif o in ("-t" or "--target"):
            target=a
        elif o in("-p","--port"):
            port=int(a)
        else:
            assert False,"Undhandled option"
