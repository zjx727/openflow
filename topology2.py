"""Topo scenario 2

Three host connect to one three port swicth:

   host --- switch  --- host (---host)

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
    "Scenario2 topology."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        #create net self
        #self = Mininet(controller=Controller)
        #add controller
        #self.addController('c0')

        # Add hosts and switches
        leftHost = self.addHost( 'h1', ip="10.0.1.100/24",defaultRoute="via 10.0.1.1" )
        underHost = self.addHost( 'h2',ip="10.0.2.100/24",defaultRoute="via 10.0.2.1" )
        rightHost = self.addHost( 'h3',ip="10.0.3.100/24",defaultRoute="via 10.0.3.1" )
        Switch = self.addSwitch( 's1' )

        # Add links
        self.addLink( leftHost, Switch )
        self.addLink( underHost, Switch )
        self.addLink( rightHost, Switch)


topos = { 'mytopo': ( lambda: MyTopo() ) }