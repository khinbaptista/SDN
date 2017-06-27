# Describe the topology

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class CustomTopology ( Topo ):
	def build(self, n = 2):
		s1 = self.addSwitch("s1")

		for h in range(n):
			host = self.addHost("h%s" % (h + 1))
			self.addLink(host, s1)

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
