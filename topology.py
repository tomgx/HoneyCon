from mininet.topo import Topo
from mininet.link import TCLink

class Topology(Topo):
    def build(self):
        # Add the central switch
        s1 = self.addSwitch('s1')

        # Connect n hosts to the switch
        hosts = []
        for h in range(0, 5):
            hosts.append(self.addHost("h{}".format(h + 1)))
            self.addLink(s1, hosts[h], cls=TCLink, bw=40, delay='15ms')


topos = {
    'topology': Topology
}