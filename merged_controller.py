#!/usr/bin/python

# SDN controller developed for the Protocolos de Comunicacao
# discipline in 2017/1
# Khin Baptista and Marcelo Vasques

# Ryu libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


# Topology discovery and routing
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from random import randint
import networkx as nx
import copy

# Token bucket
import threading # Used to schedule the main loop
import sys       # Used to get the size of each packet

class SDNController(app_manager.RyuApp):
	OFP_VERSIONS = [ ofproto_v1_3.OFP_VERSION ] # OpenFlow version 1.3

	def __init__(self, *args, **kwargs):
		super(SDNController, self).__init__(*args, **kwargs)

		# Initialize MAC address table
		self.mac_to_port = {}

		# Topology and routing
		self.raw_switches = []
		self.raw_links = []
		self.net = nx.DiGraph()

		# Token bucket
		self.queue = list()		# Main FIFO for the packets that arrive
		self.i = 0				# Token accumulator
		self.maxTokens = 640	# Maximum value of tokens to be generated
		self.tokenSize = 64		# Value used for the generation of tokens in each step
		self.initLoops()		# Initialize main loop

	# Main loop
	def initLoops(self):
		self.send_packet_if_token() # Send packets from FIFO and use tokens
		self.createToken()			# Generate new tokens every times the loop runs
		threading.Timer(1, self.initLoops).start() # Schedule a new loop run

	# Register the features of a switch with this function
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath       # Path to be used
		ofproto = datapath.ofproto		 # OpenFlow protocol
		parser = datapath.ofproto_parser

		# Intall the table-miss flow entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(
			ofproto.OFPP_CONTROLLER,
			ofproto.OFPCML_NO_BUFFER
		)]
		# Add a flow (which is basically a default action for a known packet)
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Construct flow_mod message and send it
		inst = [
			parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
		]

		mod = parser.OFPFlowMod(
			datapath = datapath,
			priority = priority,
			match = match,
			instructions = inst
		)
		# Send the message that acknowledges the flow in the switch
		datapath.send_msg(mod)

	# Setting the packet-in event function to be called
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def handler_packet_in(self, ev):
		# Getting the different message structures inside the packet
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)

		# Here we use the ethernet type that indicates the protocol of
		# the packet to actually filter the transmission, giving
		# priority to LLDP and ARP packets
		ethtype = eth_pkt.ethertype
		if ethtype == 0x88CC or ethtype == 0x806:	# Link-layer discovery protocol (LLDP) and ARP
			self.send_message(msg, False)
		elif ethtype == 0x800:						# IPv4 packets
			print("IPv4")
			self.queue.append(msg)
		else:
			self.queue.append(msg)

	# Packets that consume tokens to be sent
	def send_packet_if_token(self):
		if self.queue: # If there are packets in the FIFO
			first_in = self.queue.pop(0) # Get the first packet in the FIFO
			pkt = packet.Packet(first_in.data)

			# If there are enough tokens, send the packet
			# Otherwise, it is discarded
			if self.tokenBucket(sys.getsizeof(pkt)):
				self.send_message(first_in)

	# Sending the packet that has priority
	def send_message(self, msg, debug = True):
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# get Datapath ID to identify OpenFlow switches.
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		# analyse the received packets using the packet library.
		pkt = packet.Packet(msg.data)

		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		dst = eth_pkt.dst
		src = eth_pkt.src

		if debug: print("ETHERTYPE> " + str(eth_pkt.ethertype))

		# get the received port number from packet_in message.
		in_port = msg.match['in_port']

		if debug: self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		# If the destination MAC address is not known, FLOOD
		if src not in self.net:
			self.net.add_node(src)			# add node to the graph
			self.net.add_edge(src, dpid)	# add a link from the node to the switch
			self.net.add_edge(dpid, src, {'port':in_port})	# add a link from switch to node

		# Find the shortest path for the destiny
		if dst in self.net:
			path = nx.shortest_path(self.net, src, dst)
			if debug: print("\tPath: " + str(path))
			next = path[path.index(dpid) + 1]			# next hop in path
			out_port = self.net[dpid][next]['port']		# get output port
		else:
			out_port = ofproto.OFPP_FLOOD

		# construct action list.
		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time.
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			self.add_flow(datapath, 1, match, actions)

		# Construct a packet_out message and send it
		out = parser.OFPPacketOut(
			datapath = datapath,
			buffer_id = ofproto.OFP_NO_BUFFER,
			in_port = in_port,
			actions = actions,
			data = msg.data
		)
		datapath.send_msg(out)

	# Function that checks if there are enough tokens to send the packet
	def tokenBucket(self, tokens):
		consumed = False
		if  self.i >= tokens:
			self.i = self.i - tokens
			consumed = True
			self.logger.info("Consumed %s tokens, %s tokens available", tokens, self.i)
		return consumed

	# Part of the main loop, creates tokens until the maximum value is achieved
	def createToken(self):
		if self.i < self.maxTokens:
			self.i = self.i + self.tokenSize
			self.logger.info("Generated %s tokens, %s tokens available", self.tokenSize, self.i)
		else:
			self.logger.info("Maximum token values")

### https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md
### https://sdn-lab.com/2014/12/25/shortest-path-forwarding-with-openflow-on-ryu/
	# Topology discovery
	@set_ev_cls(event.EventSwitchEnter)
	def handler_switch_enter(self, ev):
		self.raw_switches = copy.copy(get_switch(self, None))
		self.raw_links = copy.copy(get_link(self, None))

		print("\tCurrent links:")
		for link in self.raw_links:
			print("\t\t" + str(link))

		print("\tCurrent switches:")
		for switch in self.raw_switches:
			print("\t\t" + str(switch))

		links = [
			(link.src.dpid, link.dst.dpid, {'port':link.src.port_no})
			for link in self.raw_links
		]

		self.net = nx.DiGraph()
		self.net.add_nodes_from(self.raw_switches)
		self.net.add_edges_from(links)

	@set_ev_cls(event.EventHostAdd)
	def handler_host_add(self, ev):
		print("\tNew host: " + str(ev.host))
