#!/usr/bin/python

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# Topology discovery
#from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host

class ExampleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ ofproto_v1_3.OFP_VERSION ]

	def __init__(self, *args, **kwargs):
		super(ExampleSwitch, self).__init__(*args, **kwargs)

		# Initialize MAC address table
		self.mac_to_port = {}

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
		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
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
	# Topology discovery
	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		print(ev.switch)
		return
		switch_list = get_switch(self, None)
		switches = [ switch.dp.id for switch in switch_list ]
		print("switches: ", switches)

		hosts = get_host(self, None)
		print("hosts: ", hosts)

		links_list = get_link(self, switches[0])
		links = [
			( link.src.dpid, link.dst.dpid, {'port':link.src.port_no} )
			for link in links_list
		]

		print("links: ", links)
