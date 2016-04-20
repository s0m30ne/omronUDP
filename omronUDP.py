from socket import *
import sys
from struct import pack, unpack
import time

HOST = sys.argv[1]
PORT = 9600
ADDR = (HOST, PORT)
BUFSIZE = 1024
time_out = 15

setdefaulttimeout(time_out)
s = socket(AF_INET, SOCK_DGRAM)
s.connect(ADDR)
data = bytes(bytearray([0x80,0x00,0x02,0x00,0x00,0x00,0x00,0x23,0x00,0x00,0x05,0x01,0x00]))

start_time = time.time()
s.sendto(data, ADDR)
try:
    recv_data, ADDR = s.recvfrom(BUFSIZE)
except timeout, e:
    print "[!]The port is filtered or closed. Time out."
    sys.exit()
end_time = time.time()
used_time = end_time - start_time

if recv_data:
    memcard = ("No Memory Card", "SPRAM", "EPROM", "EEPROM")
    head, Controller_Model, Controller_Version, System_Use, Area_Size, IOM_Size, DM_Words, timer, DM_Size, steps, mem_card_type, Card_Size = unpack('!B13x20s20s40sHBHBBHBH', recv_data)
    if hex(head) == '0xc0' or hex(head) == '0xc1':
        print "Host is up (%5fs latency)" % used_time
        print "PORT       STATE    SERVICE"
        print "9600/udp   open      OMRON"
        print "| OMRON Controller info:"
        print "|   Controller Model: %s" % Controller_Model
        print "|   Controller Version: %s" % Controller_Version.split('\x00')[0]
        print "|   For System Use: %s" % System_Use.split('\x00')[0]
        print "|   Program Area Size: %s" % Area_Size
        print "|   IOM Size: %s" % IOM_Size
        print "|   No. DM Words: %s" % DM_Words
        print "|   Timer/Counter: %s" % timer
        print "|   Expansion DM Size: %s" % DM_Size
        print "|   No. of steps/transitions: %s" % steps
        print "|   Kind of Memory Card: %s" % memcard[mem_card_type]
        print "|_  Memory Card Size: %s" % Card_Size
    else:
        print "[!]Returned data error!"
else:
    print "[!]None data Returned"
s.close()