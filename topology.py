#!/usr/bin/python

from mininet.topo import Topo

class CustomTopology ( Topo ):
	def build(self, n = 2):
		s1 = self.addSwitch("s1")

		for h in range(n):
			host = self.addHost("h%s" % (h + 1))
			self.addLink(host, s1)

topos = { 'mytopo' : CustomTopology }

# Run with
# sudo mn --custom topology.py --topo mytopo
