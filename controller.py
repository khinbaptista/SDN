#!/usr/bin/python

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# Topology discovery
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import copy

import networkx as nx

class ExampleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ ofproto_v1_3.OFP_VERSION ]

	def __init__(self, *args, **kwargs):
		super(ExampleSwitch, self).__init__(*args, **kwargs)

		# Initialize MAC address table
		self.mac_to_port = {}

		# Topology
		self.raw_switches = []
		self.raw_links = []
		self.net = nx.DiGraph()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Intall the table-miss flow entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(
			ofproto.OFPP_CONTROLLER,
			ofproto.OFPCML_NO_BUFFER
		)]
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

		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Get datapath ID to identify OpenFlow switches
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		# Analyse the received packets using the packet library
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		src = eth_pkt.src
		dst = eth_pkt.dst

		# Get the received port number from the packet_in message
		in_port = msg.match['in_port']

		self.logger.info("Packet in %s %s %s %s", dpid, src, dst, in_port)

		# Learn MAC address to avoid flooding next time
		self.mac_to_port[dpid][src] = in_port

		# If the destination MAC address is not known, FLOOD
		if src not in self.net:
			self.net.add_node(src)			# add node to the graph
			self.net.add_edge(src, dpid)	# add a link from the node to the switch
			self.net.add_edge(dpid, src, {'port':in_port})	# add a link from switch to node

		if dst in self.net:
			path = nx.shortest_path(self.net, src, dst)	# find shortest path
			next = path[path.index(dpid) + 1]			# next hop in path
			out_port = self.net[dpid][next]['port']		# get output port
		else:
			out_port = ofproto.OFPP_FLOOD

		# Construct action list
		actions = [ parser.OFPActionOutput(out_port) ]

		# Install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port = in_port, eth_dst = dst)
			self.add_flow(datapath, 1, match, actions)

		# Constructa packet_out message and send it
		out = parser.OFPPacketOut(
			datapath = datapath,
			buffer_id = ofproto.OFP_NO_BUFFER,
			in_port = in_port,
			actions = actions,
			data = msg.data
		)

		datapath.send_msg(out)

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

		self.net = nx.DiGraph()
		self.net.add_nodes_from(self.raw_switches)
		self.net.add_edges_from(self.raw_links)
