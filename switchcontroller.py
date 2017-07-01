# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import threading
import sys


class SwitchController(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SwitchController, self).__init__(*args, **kwargs)
		# initialize mac address table.
		self.mac_to_port = {}
		self.queue = list()
		self.i = 0
		self.maxTokens = 640
		self.tokenSize = 64
		self.initLoops()

	def initLoops(self):
		#self.logger.info("oi")
		self.send_packet()
		self.createToken()
		threading.Timer(1, self.initLoops).start()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install the table-miss flow entry.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# construct flow_mod message and send it.
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
								match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		self.queue.append(msg)

	def send_packet(self):
		if self.queue:
			first_in = self.queue.pop(0)

			datapath = first_in.datapath
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser

			# get Datapath ID to identify OpenFlow switches.
			dpid = datapath.id
			self.mac_to_port.setdefault(dpid, {})

			# analyse the received packets using the packet library.
			pkt = packet.Packet(first_in.data)

			if self.tokenBucket(sys.getsizeof(pkt)):
				eth_pkt = pkt.get_protocol(ethernet.ethernet)
				dst = eth_pkt.dst
				src = eth_pkt.src

				# get the received port number from packet_in message.
				in_port = first_in.match['in_port']

				self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

				# learn a mac address to avoid FLOOD next time.
				self.mac_to_port[dpid][src] = in_port

				# if the destination mac address is already learned,
				# decide which port to output the packet, otherwise FLOOD.
				if dst in self.mac_to_port[dpid]:
					out_port = self.mac_to_port[dpid][dst]
				else:
					out_port = ofproto.OFPP_FLOOD

				# construct action list.
				actions = [parser.OFPActionOutput(out_port)]

				# install a flow to avoid packet_in next time.
				if out_port != ofproto.OFPP_FLOOD:
					match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
					self.add_flow(datapath, 1, match, actions)

				# construct packet_out message and send it.
				out = parser.OFPPacketOut(datapath=datapath,
										  buffer_id=ofproto.OFP_NO_BUFFER,
										  in_port=in_port, actions=actions,
										  data=first_in.data)
				datapath.send_msg(out)

	def tokenBucket(self, tokens):
		consumed = False
		if  self.i >= tokens:
			self.i = self.i - tokens
			consumed = True
			self.logger.info("Consumed %s tokens, %s tokens available", tokens, self.i)
		return consumed

	def createToken(self):
		if self.i < self.maxTokens:
			self.i = self.i + self.tokenSize
			self.logger.info("Generated %s tokens, %s tokens available", self.tokenSize, self.i)
		else:
			self.logger.info("Maximum token values")
