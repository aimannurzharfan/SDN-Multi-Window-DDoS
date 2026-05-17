#!/usr/bin/env python3
"""
5-switch, 20-host tree topology for the multi-window DDoS detection thesis.

                  [Ryu Controller @ 127.0.0.1:6653]
                              |
                             s1                     <- root
                            /  \
                          s2    s3                  <- intermediate
                          |      |
                         s4      s5                 <- leaf
                         /|\     /|\
                       h1-h10  h11-h20

Hosts:
  h1  - h15 : legitimate (h1-h10 on s4, h11-h15 on s5)
  h16 - h20 : attackers  (on s5)
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_topology():
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    info("*** Adding Ryu remote controller\n")
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=6653)

    info("*** Adding 5 switches\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", protocols="OpenFlow13")
    s5 = net.addSwitch("s5", protocols="OpenFlow13")

    info("*** Adding 20 hosts\n")
    hosts = []
    for i in range(1, 21):
        hosts.append(net.addHost(f"h{i}", ip=f"10.0.0.{i}/24"))

    info("*** Wiring switch backbone\n")
    net.addLink(s1, s2, bw=1000)
    net.addLink(s1, s3, bw=1000)
    net.addLink(s2, s4, bw=100)
    net.addLink(s3, s5, bw=100)

    info("*** Attaching h1-h10 (legitimate) to s4\n")
    for h in hosts[0:10]:
        net.addLink(h, s4)

    info("*** Attaching h11-h15 (legitimate) and h16-h20 (attackers) to s5\n")
    for h in hosts[10:20]:
        net.addLink(h, s5)

    return net


def main():
    setLogLevel("info")
    net = build_topology()
    info("*** Starting network\n")
    net.start()
    info("*** Ready. Type 'pingall' to test, 'exit' to quit.\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    main()