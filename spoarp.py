import sys
import socket
import getopt
import threading
import subprocess
import nmap
from scapy.all import *
#from testlib import *


def usage():
    print "Spoarp\n"
    
    print "Usage: spoarp.py -t target_network -m mask "
    #print "-l --listen                - listen on [host]:[port] for incomming connection"
    print
    print "Examples:"
    print "spoarp.py -t 192.168.0.0 -m 24"
    sys.exit(0)

def main():
    global target
    global mask
    nbTarget=0

    if not len(sys.argv[1:]): usage()
    #read command options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:m:",["help","target","mask"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o,a in opts:
        if o in ("-h" or "--help"):
            usage()
	elif o in ("-t" or "--target"):
	    nbTarget+=1
	    target = a
	elif o in("-m" or "--mask"):
	    mask = a	
        else:
            assert False,"Undhandled option"

    if nbTarget<1:
	print("Please choose a target")
	usage()


main()
