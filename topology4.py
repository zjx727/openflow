"""Topo scenario 4

Three three-port switches each connected with three hosts

  (host ---) (host ---) host --- switch --- switch --- host (--- host) (--- host) --- switch --- host (--- host) (--- host)

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
    "Scenario 4 topology."

    def __init__( self ):
        "Create custom topo."
        
        # Initialize topology
        Topo.__init__( self )
        
        # Add hosts and switches
        leftHost1 = self.addHost('h4', ip="10.0.1.4/24",defaultRoute="via 10.0.1.1")
        leftHost2 = self.addHost('h5', ip="10.0.1.5/24",defaultRoute="via 10.0.1.1")
        leftHost3 = self.addHost('h6', ip="10.0.1.6/24",defaultRoute="via 10.0.1.1")
        
        rightHost1 = self.addHost('h10',ip="10.0.3.10/24",defaultRoute="via 10.0.3.1")
        rightHost2 = self.addHost('h11',ip="10.0.3.11/24",defaultRoute="via 10.0.3.1")
        rightHost3 = self.addHost('h12',ip="10.0.3.12/24",defaultRoute="via 10.0.3.1")
        
        upHost1 = self.addHost('h7',ip="10.0.2.7/24",defaultRoute="via 10.0.2.1")
        upHost2 = self.addHost('h8',ip="10.0.2.8/24",defaultRoute="via 10.0.2.1")
        upHost3 = self.addHost('h9',ip="10.0.2.9/24",defaultRoute="via 10.0.2.1")
        
        Switch1= self.addSwitch('s1')
        Switch2= self.addSwitch('s2')
        Switch3= self.addSwitch('s3')
        
        # Add links
        self.addLink( leftHost1, Switch1, port1 = 1, port2 = 4)
        self.addLink( leftHost2, Switch1, port1 = 1, port2 = 5 )
        self.addLink( leftHost3, Switch1, port1 = 1, port2 = 6 )
        
        self.addLink( rightHost1, Switch3, port1 = 1, port2 = 10 )
        self.addLink( rightHost2, Switch3, port1 = 1, port2 = 11 )
        self.addLink( rightHost3, Switch3, port1 = 1, port2 = 12 )
        
        self.addLink( upHost1, Switch2, port1 = 1, port2 = 7 )
        self.addLink( upHost2, Switch2, port1 = 1, port2 = 8 )
        self.addLink( upHost3, Switch2, port1 = 1, port2 = 9 )
        
        self.addLink( Switch1, Switch2, port1 = 1, port2 = 1)
        self.addLink( Switch1, Switch3, port1 = 2, port2 = 2)
        self.addLink( Switch3, Switch2, port1 = 3, port2 = 3)

topos = { 'mytopo': ( lambda: MyTopo() ) }