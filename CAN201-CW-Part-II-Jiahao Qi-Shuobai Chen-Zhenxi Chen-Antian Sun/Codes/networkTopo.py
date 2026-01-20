#!/usr/bin/python
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm


def Topo():
    net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24')

    # add controller
    controller = net.addController('c0', RemoteController)

    # add hosts
    server1 = net.addHost('server1', cls=Host, ip='10.0.1.2/24', defaultRoute=None)
    server2 = net.addHost('server2', cls=Host, ip='10.0.1.3/24', defaultRoute=None)
    client = net.addHost('client', cls=Host, ip='10.0.1.5/24', defaultRoute=None)

    # add switch
    sdn_switch = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='secure')

    # add links
    net.addLink(server1, sdn_switch)
    net.addLink(server2, sdn_switch)
    net.addLink(client, sdn_switch)

    # set MAC to interfac
    server1.setMAC(mac="00:00:00:00:00:01")
    server2.setMAC(mac="00:00:00:00:00:02")
    client.setMAC(mac="00:00:00:00:00:03")

    # network build & start(controller -> switch)
    net.build()
    controller.start()
    sdn_switch.start([controller])

    # start xterms
    net.terms += makeTerm(server1)
    net.terms += makeTerm(server2)
    net.terms += makeTerm(client)
    net.terms += makeTerm(controller)
    net.terms += makeTerm(sdn_switch)

    # CLI mode running
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    Topo()