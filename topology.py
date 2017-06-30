#!/usr/bin/python

from mininet.topo import Topo

class CustomTopology ( Topo ):
	def build(self, n = 2):
		switches = []
		for i in range(7):
			switches.append(self.addSwitch("s%d" % (i + 1)))
		self.addLink("s1", "s2")
		self.addLink("s2", "s3")
		self.addLink("s2", "s4")
		self.addLink("s1", "s5")
		self.addLink("s5", "s6")
		self.addLink("s5", "s7")

		self.host_count = 0
		self.add_hosts_to_switch(switches[0], n)
		self.add_hosts_to_switch(switches[2], n)
		self.add_hosts_to_switch(switches[3], n)
		self.add_hosts_to_switch(switches[5], n)
		self.add_hosts_to_switch(switches[6], n)

	def add_hosts_to_switch(self, switch, n):
		for i in range(n):
			host = self.addHost("h%d" % (self.host_count + 1))
			self.host_count += 1
			self.addLink(switch, host)

topos = { 'mytopo' : CustomTopology }

# Run with
# sudo mn --custom topology.py --topo mytopo
