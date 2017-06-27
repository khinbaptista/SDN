# Describe the topology

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class CustomTopology ( Topo ):
	def build(self, n = 2):
		s1 = self.addSwitch("s1")

		for h in range(n):
			host = self.addHost("h%s" % (h + 1))
			self.addLink(h, s1)

def test():
	topo	= CustomTopology(n = 4)
	net		= Mininet(topo)
	net.start()

	print "Dumping host connections"
	dumpNodeConnections(net.hosts)

	print "Testing network connectivity"
	net.pingAll()
	net.stop()

if __name__ == "__main__":
	setLogLevel("info")
	test()
