#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces
import random

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?q=falun+gong HTTP/1.1\nHost: www.google.com\n\n"

# A couple useful functions that take scapy packets
def isRST(p):
	return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
	return ICMP in p

def isTimeExceeded(p):
	return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
	def __init__(self, dst=None):
		# Get one's SRC IP & interface
		i = interfaces.interfaces()
		self.src = i[1][0]
		self.iface = i[0]
		self.netmask = i[1][1]
		self.enet = i[2]
		self.dst = dst
		sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
						 (self.src, self.iface, self.netmask, self.enet))

		# A queue where received packets go.  If it is full
		# packets are dropped.
		self.packetQueue = Queue.Queue(100000)
		self.dropCount = 0
		self.idcount = 0

		self.ethrdst = ""

		# Get the destination ethernet address with an ARP
		self.arp()
		
		# You can add other stuff in here to, e.g. keep track of
		# outstanding ports, etc.
		
		# Start the packet sniffer
		t = threading.Thread(target=self.run_sniffer)
		t.daemon = True
		t.start()
		time.sleep(.1)

	# generates an ARP request
	def arp(self):
		e = Ether(dst="ff:ff:ff:ff:ff:ff",
				  type=0x0806)
		gateway = ""
		srcs = self.src.split('.')
		netmask = self.netmask.split('.')
		for x in range(4):
			nm = int(netmask[x])
			addr = int(srcs[x])
			if x == 3:
				gateway += "%i" % ((addr & nm) + 1)
			else:
				gateway += ("%i" % (addr & nm)) + "."
		sys.stderr.write("Gateway %s\n" % gateway)
		a = ARP(hwsrc=self.enet,
				pdst=gateway)
		p = srp1([e/a], iface=self.iface, verbose=0)
		self.etherdst = p[Ether].src
		sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


	# A function to send an individual packet.
	def send_pkt(self, payload=None, ttl=32, flags="",
				 seq=None, ack=None,
				 sport=None, dport=80,ipid=None,
				 dip=None,debug=False):
		if sport == None:
			sport = random.randint(1024, 32000)
		if seq == None:
			seq = random.randint(1, 31313131)
		if ack == None:
			ack = random.randint(1, 31313131)
		if ipid == None:
			ipid = self.idcount
			self.idcount += 1
		t = TCP(sport=sport, dport=dport,
				flags=flags, seq=seq, ack=ack)
		ip = IP(src=self.src,
				dst=self.dst,
				id=ipid,
				ttl=ttl)
		p = ip/t
		if payload:
			p = ip/t/payload
		else:
			pass
		e = Ether(dst=self.etherdst,
				  type=0x0800)
		# Have to send as Ethernet to avoid interface issues
		sendp([e/p], verbose=1, iface=self.iface)
		# Limit to 20 PPS.
		time.sleep(.05)
		# And return the packet for reference
		return p


	# Has an automatic 5 second timeout.
	def get_pkt(self, timeout=5):
		try:
			return self.packetQueue.get(True, timeout)
		except Queue.Empty:
			return None

	# The function that actually does the sniffing
	def sniffer(self, packet):
		try:
			# non-blocking: if it fails, it fails
			self.packetQueue.put(packet, False)
		except Queue.Full:
			if self.dropCount % 1000 == 0:
				sys.stderr.write("*")
				sys.stderr.flush()
			self.dropCount += 1

	def run_sniffer(self):
		sys.stderr.write("Sniffer started\n")
		rule = "src net %s or icmp" % self.dst
		sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
		sniff(prn=self.sniffer,
			  filter=rule,
			  iface=self.iface,
			  store=0)

	# Sends the message to the target in such a way
	# that the target receives the msg without
	# interference by the Great Firewall.
	#
	# ttl is a ttl which triggers the Great Firewall but is before the
	# server itself (from a previous traceroute incantation
	def evade(self, target, msg, ttl):

		while (self.packetQueue.qsize() > 0):
			print(self.packetQueue.qsize())
			trash = self.get_pkt()

		port_number = random.randint(2000, 30000)
		TCP_SYN = self.send_pkt(flags="S", sport=port_number, ttl=100)
		SYN_ACK = self.get_pkt()
		if (SYN_ACK == None):
			return
		else:
			while True:
				if ((TCP in SYN_ACK) and (SYN_ACK[IP][TCP].flags & 0x12 != 0) and (SYN_ACK.ack == TCP_SYN.seq+1) and (SYN_ACK[IP][TCP].dport == port_number)):
					break
				else:
					SYN_ACK = self.get_pkt()
					if (SYN_ACK == None):
						return

		seqi = SYN_ACK.ack
		acki = SYN_ACK.seq+1
		for i in range(len(msg)):
			char = msg[i]
			DATA = self.send_pkt(flags="PA", payload=char, seq=seqi, ack=acki, sport=port_number, ttl=100)

			ack = self.get_pkt()
			while (ack == None):
				self.send_pkt(flags="PA", payload=char, seq=seqi, ack=acki, sport=port_number, ttl=100)
				ack = self.get_pkt()
			
			while True:
				if ((TCP in ack) and (ack[IP][TCP].flags & 0x12 != 0) and (ack.ack == seqi+1) and (ack[IP][TCP].dport == port_number)):
					break
				else:
					ack = self.get_pkt()
					while (ack == None):
						self.send_pkt(flags="PA", payload=char, seq=seqi, ack=acki, sport=port_number, ttl=100)
						ack = self.get_pkt()

			seqi = ack.ack
			acki = ack.seq


		ret = ""
		#credit to Mingwei Samuel on piazza. he posted up to the #do stuff
		timeout = time.time() + 5
		while 1:
			rp = self.get_pkt(max(0, timeout - time.time()))
			if not rp:
				break
			#do stuff
			ret += str(rp.payload)
		return ret

		
	# Returns "DEAD" if server isn't alive,
	# "LIVE" if teh server is alive,
	# "FIREWALL" if it is behind the Great Firewall
	def ping(self, target):
		# self.send_msg([triggerfetch], dst=target, syn=True)
		DEAD = "DEAD"
		LIVE = "LIVE"
		FIREWALL = "FIREWALL"

		port_number = random.randint(2000, 30000)

		#while (self.packetQueue.qsize() > 0):
		#	print(self.packetQueue.qsize())
		#	trash = self.get_pkt()

		TCP_SYN = self.send_pkt(flags="S", sport=port_number)

		SYN_ACK = self.get_pkt()
		if (SYN_ACK == None):
			return DEAD
		else:
			while True:
				if ((TCP in SYN_ACK) and (SYN_ACK[IP][TCP].flags & 0x12 != 0) and (SYN_ACK.ack == TCP_SYN.seq+1) and (SYN_ACK[IP][TCP].dport == port_number)):
					break
				else:
					SYN_ACK = self.get_pkt()
					if (SYN_ACK == None):
						return DEAD



		ACK = self.send_pkt(flags="A", seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=port_number)
		#pLoad = "GET /search?q=falun+gong HTTP/1.1 \r\n host:www.google.com\r\n\r\n"
		data_Packet = self.send_pkt(flags="PA", payload=triggerfetch, seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=port_number)
		
		response=self.get_pkt()
		while (response != None):
			if ((TCP in response) and (response[IP][TCP].dport == port_number) and isRST(response)):
				return FIREWALL
			else:
				response=self.get_pkt()
				if response == None:
					break
		return LIVE



		#if ((response[IP][TCP].dport == port_number) and isRST(response)):
		#		return FIREWALL
		#while (self.packetQueue.qsize() > 0):
		#	print(self.packetQueue.qsize())
		#	response=self.get_pkt()
		#	if ((TCP in response) and (response[IP][TCP].dport == port_number) and isRST(response)):
		#		return FIREWALL
		#return LIVE

			

	# Format is
	# ([], [])
	# The first list is the list of IPs that have a hop
	# or none if none
	# The second list is T/F 
	# if there is a RST back for that particular request
	def traceroute(self, target, hops):
		ips, tfs = [], []
		
		seenRST = False
		for i in range(hops):
			ips.append(None)
			if (seenRST):
				tfs.append(True)
			else:
				tfs.append(False)

			sPort = random.randint(2000, 30000)

			# Empty the queue prior to new handshake
			while(self.packetQueue.qsize() > 0):
				self.get_pkt(timeout=.4)


			# Start-handshake
			SYN = self.send_pkt(sport=sPort, flags="S")
			SYN_ACK = self.get_pkt(timeout=1)
			if ((SYN_ACK is None) or (SYN_ACK.seq is None)):
				continue
			else:
				ACK = self.send_pkt(flags="A", seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=sPort, dip=target)
			# End-handshake

			# Send 3 packets
			self.send_pkt(payload=triggerfetch, ttl=i+1, flags="PA", seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=sPort, dport=80)
			self.send_pkt(payload=triggerfetch, ttl=i+1, flags="PA", seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=sPort, dport=80)
			self.send_pkt(payload=triggerfetch, ttl=i+1, flags="PA", seq=SYN_ACK.ack, ack=SYN_ACK.seq+1, sport=sPort, dport=80)

			res = self.get_pkt(timeout=1)
			while (res != None):
				if (res == None):
					ips[i] = None
					tfs[i] = False
					break
				else:
					if (isICMP(res) and isTimeExceeded(res)):
						ips[i] = res[IP].src
						if (seenRST):
							tfs[i] = True
						else:
							tfs[i] = False
					if (isRST(res)):
						if(not seenRST):
							seenRST = True
						tfs[i] = True
				res = self.get_pkt(timeout=1)
		return (ips, tfs)

