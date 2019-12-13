"""Topo scenario 3

Three host connect to one three port swicth:

  (host ---) host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=`mytopo' from the command line.
"""

import time
from mininet.net import Mininet
from mininet.node import RemoteController, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel,info
from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Scenario 3 topology."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

		#create net self
		#self = Mininet(controller=Controller)
		#add controller
		#self.addController('c0')


        # Add hosts and switches
        leftHost1= self.addHost( 'h3', ip="10.0.1.2/24",defaultRoute="via 10.0.1.1")
        leftHost2= self.addHost( 'h4', ip="10.0.1.3/24",defaultRoute="via 10.0.1.1")
        rightHost = self.addHost( 'h5',ip="10.0.2.2/24",defaultRoute="via 10.0.2.1")
        Switch1= self.addSwitch( 's1' )
        Switch2= self.addSwitch( 's2' )

        # Add links
        self.addLink( leftHost1, Switch1, port1 =1, port2 =2 )
        self.addLink( leftHost2, Switch1, port1 =1, port2 =3)
        self.addLink( rightHost, Switch2, port1 =1, port2 =2)
        self.addLink( Switch1, Switch2, port1 =1, port2 =1)

topos = { 'mytopo': ( lambda: MyTopo() ) }

