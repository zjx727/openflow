from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import *

log = core.getLogger()

_arp_cache = {IPAddr('10.0.1.1'):EthAddr('00:00:00:00:01:04'),IPAddr('10.0.2.1'):EthAddr('00:00:00:00:02:07'),IPAddr('10.0.3.1'):EthAddr('00:00:00:00:03:10'),'1':EthAddr('00:00:00:00:00:05'),'2':EthAddr('00:00:00:00:00:06'),'3':EthAddr('00:00:00:00:00:06'),EthAddr('00:00:00:00:01:01'):IPAddr('10.0.4.1'),EthAddr('00:00:00:00:01:02'):IPAddr('10.0.5.1'),EthAddr('00:00:00:00:02:01'):IPAddr('10.0.4.2'),EthAddr('00:00:00:00:02:03'):IPAddr('10.0.6.2'),EthAddr('00:00:00:00:03:03'):IPAddr('10.0.6.3'),EthAddr('00:00:00:00:03:02'):IPAddr('10.0.5.3')}

_route1=([(IPAddr('10.0.1.4'),IPAddr('10.0.1.1'),4,'10.0.1.0/24',EthAddr('00:00:00:00:01:04')),(IPAddr('10.0.1.5'),IPAddr('10.0.1.1'),5,'10.0.1.0/24',EthAddr('00:00:00:00:01:04')),(IPAddr('10.0.1.6'),IPAddr('10.0.1.1'),6,'10.0.1.0/24',EthAddr('00:00:00:00:01:04')),(IPAddr('10.0.2.7'),IPAddr('10.0.2.1'),1,'10.0.2.0/24',EthAddr('00:00:00:00:01:01')),(IPAddr('10.0.2.8'),IPAddr('10.0.2.1'),1,'10.0.2.0/24',EthAddr('00:00:00:00:01:01')),(IPAddr('10.0.2.9'),IPAddr('10.0.2.1'),1,'10.0.2.0/24',EthAddr('00:00:00:00:01:01')),(IPAddr('10.0.3.10'),IPAddr('10.0.3.1'),2,'10.0.3.0/24',EthAddr('00:00:00:00:01:02')),(IPAddr('10.0.3.11'),IPAddr('10.0.3.1'),2,'10.0.3.0/24',EthAddr('00:00:00:00:01:02')),(IPAddr('10.0.3.12'),IPAddr('10.0.3.1'),2,'10.0.3.0/24',EthAddr('00:00:00:00:01:02'))])

_route2=([(IPAddr('10.0.1.4'),IPAddr('10.0.1.1'),1,'10.0.1.0/24',EthAddr('00:00:00:00:02:01')),(IPAddr('10.0.1.5'),IPAddr('10.0.1.1'),1,'10.0.1.0/24',EthAddr('00:00:00:00:02:01')),(IPAddr('10.0.1.6'),IPAddr('10.0.1.1'),1,'10.0.1.0/24',EthAddr('00:00:00:00:02:01')),(IPAddr('10.0.2.7'),IPAddr('10.0.2.1'),7,'10.0.2.0/24',EthAddr('00:00:00:00:02:07')),(IPAddr('10.0.2.8'),IPAddr('10.0.2.1'),8,'10.0.2.0/24',EthAddr('00:00:00:00:01:07')),(IPAddr('10.0.2.9'),IPAddr('10.0.2.1'),9,'10.0.2.0/24',EthAddr('00:00:00:00:01:07')),(IPAddr('10.0.3.10'),IPAddr('10.0.3.1'),3,'10.0.3.0/24',EthAddr('00:00:00:00:02:03')),(IPAddr('10.0.3.11'),IPAddr('10.0.3.1'),3,'10.0.3.0/24',EthAddr('00:00:00:00:02:03')),(IPAddr('10.0.3.12'),IPAddr('10.0.3.1'),3,'10.0.3.0/24',EthAddr('00:00:00:00:02:03'))])

_route3=([(IPAddr('10.0.1.4'),IPAddr('10.0.1.1'),2,'10.0.1.0/24',EthAddr('00:00:00:00:03:02')),(IPAddr('10.0.1.5'),IPAddr('10.0.1.1'),2,'10.0.1.0/24',EthAddr('00:00:00:00:03:02')),(IPAddr('10.0.1.6'),IPAddr('10.0.1.1'),2,'10.0.1.0/24',EthAddr('00:00:00:00:03:02')),(IPAddr('10.0.2.7'),IPAddr('10.0.2.1'),3,'10.0.2.0/24',EthAddr('00:00:00:00:03:03')),(IPAddr('10.0.2.8'),IPAddr('10.0.2.1'),3,'10.0.2.0/24',EthAddr('00:00:00:00:03:03')),(IPAddr('10.0.2.9'),IPAddr('10.0.2.1'),3,'10.0.2.0/24',EthAddr('00:00:00:00:03:03')),(IPAddr('10.0.3.10'),IPAddr('10.0.3.1'),10,'10.0.3.0/24',EthAddr('00:00:00:00:03:10')),(IPAddr('10.0.3.11'),IPAddr('10.0.3.1'),11,'10.0.3.0/24',EthAddr('00:00:00:00:03:10')),(IPAddr('10.0.3.12'),IPAddr('10.0.3.1'),12,'10.0.3.0/24',EthAddr('00:00:00:00:03:10'))])

_port_to_mac_1 = {'1':EthAddr('00:00:00:00:01:01'),'2':EthAddr('00:00:00:00:01:02'),'4':EthAddr('00:00:00:00:01:04'),'5':EthAddr('00:00:00:00:01:04'),'6':EthAddr('00:00:00:00:01:04')}
_port_to_mac_2 = {'1':EthAddr('00:00:00:00:02:01'),'3':EthAddr('00:00:00:00:02:03')}
_port_to_mac_3 = {'2':EthAddr('00:00:00:00:03:02'),'3':EthAddr('00:00:00:00:03:03')}
_ip_to_port = {}

rqtsrc,rqtdst,rqtport,rqtpfx,rqthwsrc=0,0,0,0,0
rplsrc,rpldst,rplport,rplpfx,rplhwsrc=0,0,0,0,0
icmpf=icmp()
ip_pakt = ipv4()
eth = ethernet()
_buff={}
_ip_bf={}

class controller4 (object):
    '**********begin***************************'
    def __init__ (self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        
    '******************************************'
    def resend_packet (self, packet_in, out_port):
            msg = of.ofp_packet_out()
            msg.data = packet_in

            # Add an action to send to the specified port
            action = of.ofp_action_output(port = out_port)
            msg.actions.append(action)
            #msg.idle_timeout=180
            #msg.hard_timeout=1000
            # Send message to switch
            self.connection.send(msg)
    '******************************************'
    def msg_send (self,packet,hwsrc,hwdst,port):
        msg = of.ofp_packet_out()
        msg.data=packet
        msg.actions.append(of.ofp_action_dl_addr.set_src(hwsrc))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(hwdst))
        msg.actions.append(of.ofp_action_output(port = port))
        self.connection.send(msg)  
    '******************************************'
    def tcp_send (self,packet,hwsrc,hwdst,srcip,dstip,port):
        msg = of.ofp_packet_out()
        msg.data=packet
        msg.actions.append(of.ofp_action_dl_addr.set_src(hwsrc))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(hwdst))
        msg.actions.append(of.ofp_action_nw_addr.set_src(srcip))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(dstip))
        msg.actions.append(of.ofp_action_output(port = port))
        self.connection.send(msg)
    '******************************************'
    def arp_request (self,packet,src_ip,src_mac,port):

            p =arp()
            p.hwtype = arp.HW_TYPE_ETHERNET
            p.prototype = arp.PROTO_TYPE_IP
            p.hwlen = 6
            p.protolen = 4
            p.opcode = arp.REQUEST
            p.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
            p.hwsrc = src_mac
            p.protodst = packet.payload.dstip
            p.protosrc = src_ip
            
            E = ethernet(type=ethernet.ARP_TYPE, src=p.hwsrc,dst=p.hwdst)
            E.payload = p
            
            self.resend_packet (E, port)
    '******************************************'
    def icmp_forward(self,payload,icmp_type,ip_src,ip_dst,mac_src,mac_dst,out_port):
            global icmpf,ip_pakt,eth
            icmpf = icmp()
            icmpf.type = icmp_type
            icmpf.payload = payload

            ip_pakt = ipv4()
            ip_pakt.protocol = ip_pakt.ICMP_PROTOCOL
            ip_pakt.srcip = ip_src
            ip_pakt.dstip = ip_dst
            #log.debug('Forward ICMP %s from src_IP %s and dst_IP %s' %(icmp_type, ip_pakt.srcip, ip_pakt.dstip))

            eth = ethernet()
            eth.src = mac_src
            eth.dst = mac_dst
            eth.type = eth.IP_TYPE

            ip_pakt.payload = icmpf
            eth.payload = ip_pakt

            self.resend_packet (eth, out_port)
            #log.debug("ICMP from port%s which MAC is %s to MAC: %s" %(out_port, mac_src, mac_dst))
    '******************************************'
    def icmp_unknownhost(self,p,interfaceip,out_port):
            global icmpf,ip_pakt,eth
            u = icmp()
            u.type = TYPE_DEST_UNREACH
            u.code = 1
            
            orig_ip = p.payload
            d = orig_ip.pack()
            d = d[:orig_ip.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d # network, unsigned short, unsigned short
            u.payload = d

            ip_pakt = ipv4()
            ip_pakt.protocol = ip_pakt.ICMP_PROTOCOL
            ip_pakt.srcip = interfaceip
            ip_pakt.dstip = p.payload.srcip
            #log.debug('Forward ICMP %s from src_IP %s and dst_IP %s' %(icmp_type, ip_pakt.srcip, ip_pakt.dstip))

            eth = ethernet()
            eth.src =p.dst
            eth.dst =p.src
            eth.type = eth.IP_TYPE

            ip_pakt.payload = u
            eth.payload = ip_pakt

            self.resend_packet (eth, out_port)
            #log.debug("ICMP from port%s which MAC is %s to MAC: %s" %(out_port, mac_src, mac_dst))    
    
    '**************************************************************************'
    def _handle_PacketIn (self,event):

        log.info('Start main funciton')
        dpid = event.connection.dpid
        log.info('dpid is %s ' %dpid)
        packet = event.parsed # This is the parsed packet data.
        inport = event.port
        if not packet.parsed:
            log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return
        packet_in = event.ofp # The actual ofp_packet_in message.


        log.info("Installing flow...")
        # Maybe the log statement should have source/destination/port?
        log.debug('the source MAC is %s' %packet.src)
        log.debug('the dist MAC is %s' %packet.dst)
        log.debug('the source port is %s' %packet_in.in_port)
        if dpid == 1:
            _route = _route1
        elif dpid == 2:
            _route = _route2
        else:
            _route = _route3
        '***********************ARP**********************************'
        if packet.find("arp"):
            a= packet.find('arp')
            if not a : return
            _ip_to_port[a.protosrc] = inport
            log.debug("ARP %s %s => %s",{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
                
            #Deal with ARP REQUEST then ARP REPLY to hosts
            if a.prototype == arp.PROTO_TYPE_IP and a.hwtype == arp.HW_TYPE_ETHERNET and a.opcode == arp.REQUEST:
                _arp_cache[IPAddr(a.protosrc)]=EthAddr(a.hwsrc)
                if dpid == 1:
                    if inport == 1 or inport == 2:
                        #broadcast arp request from r1
                        p =arp()
                        p.hwtype = arp.HW_TYPE_ETHERNET
                        p.prototype = arp.PROTO_TYPE_IP
                        p.hwlen = 6
                        p.protolen = 4
                        p.opcode = arp.REQUEST
                        p.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
                        p.hwsrc = EthAddr('00:00:00:00:01:04')
                        p.protodst = a.protodst
                        p.protosrc = IPAddr('10.0.1.1')
                        
                        E = ethernet(type=ethernet.ARP_TYPE, src=p.hwsrc,dst=p.hwdst)
                        E.payload = p
                        self.resend_packet (E, 4)
                        self.resend_packet (E, 5)
                        self.resend_packet (E, 6)
                    else:
                        #reply to host the router's mac
                        r = arp()
                        r.hwtype = a.hwtype
                        r.prototype = a.prototype
                        r.hwlen = a.hwlen
                        r.protolen = a.protolen
                        r.opcode = arp.REPLY
                        r.hwdst = a.hwsrc
                        r.protodst = a.protosrc
                        r.protosrc = a.protodst
                        r.hwsrc=EthAddr('00:00:00:00:01:04')
                        
                        e = ethernet(type=packet.type, src=r.hwsrc,dst=a.hwsrc)
                        e.payload = r
                        log.info("Answering ARP for %s" % (str(r.protosrc)))
                        
                        msg = of.ofp_packet_out()
                        msg.data = e.pack()
                        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                        msg.in_port = inport
                        event.connection.send(msg)
                        
                        msg1 = of.ofp_flow_mod()
                        msg1.match = of.ofp_match()
                        msg1.match.dl_type=0x800
                        msg1.match.nw_dst=a.protosrc
                        msg1.actions.append(of.ofp_action_dl_addr.set_src(r.hwsrc))
                        msg1.actions.append(of.ofp_action_dl_addr.set_dst(r.hwdst))
                        msg1.actions.append(of.ofp_action_output(port=inport))
                        self.connection.send(msg1)
                        
                elif dpid == 2:
                    if inport == 1 or inport == 3:
                        #broadcast arp request from r1 or r3
                        p2 =arp()
                        p2.hwtype = arp.HW_TYPE_ETHERNET
                        p2.prototype = arp.PROTO_TYPE_IP
                        p2.hwlen = 6
                        p2.protolen = 4
                        p2.opcode = arp.REQUEST
                        p2.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
                        p2.hwsrc = EthAddr('00:00:00:00:02:07')
                        p2.protodst = a.protodst
                        p2.protosrc = IPAddr('10.0.2.1')
                        
                        E2 = ethernet(type=ethernet.ARP_TYPE, src=p2.hwsrc,dst=p2.hwdst)
                        E2.payload = p2
                        self.resend_packet (E2, 7)
                        self.resend_packet (E2, 8)
                        self.resend_packet (E2, 9)
                    else:
                        #reply to host the router's mac
                        r2 = arp()
                        r2.hwtype = a.hwtype
                        r2.prototype = a.prototype
                        r2.hwlen = a.hwlen
                        r2.protolen = a.protolen
                        r2.opcode = arp.REPLY
                        r2.hwdst = a.hwsrc
                        r2.protodst = a.protosrc
                        r2.protosrc = a.protodst
                        r2.hwsrc=EthAddr('00:00:00:00:02:07')
                        
                        e2 = ethernet(type=packet.type, src=r2.hwsrc,dst=a.hwsrc)
                        e2.payload = r2
                        
                        msg2 = of.ofp_packet_out()
                        msg2.data = e2.pack()
                        msg2.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                        msg2.in_port = inport
                        event.connection.send(msg2)
                        
                        msg22 = of.ofp_flow_mod()
                        msg22.match = of.ofp_match()
                        msg22.match.dl_type=0x800
                        msg22.match.nw_dst=a.protosrc
                        msg22.actions.append(of.ofp_action_dl_addr.set_src(r2.hwsrc))
                        msg22.actions.append(of.ofp_action_dl_addr.set_dst(r2.hwdst))
                        msg22.actions.append(of.ofp_action_output(port=inport))
                        self.connection.send(msg22)
                else:
                    if inport == 2 or inport == 3:
                        #broadcast arp request from r1
                        p3 =arp()
                        p3.hwtype = arp.HW_TYPE_ETHERNET
                        p3.prototype = arp.PROTO_TYPE_IP
                        p3.hwlen = 6
                        p3.protolen = 4
                        p3.opcode = arp.REQUEST
                        p3.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
                        p3.hwsrc = EthAddr('00:00:00:00:03:10')
                        p3.protodst = a.protodst
                        p3.protosrc = IPAddr('10.0.3.1')
                        
                        E3 = ethernet(type=ethernet.ARP_TYPE, src=p3.hwsrc,dst=p3.hwdst)
                        E3.payload = p3
                        self.resend_packet (E3, 10)
                        self.resend_packet (E3, 11)
                        self.resend_packet (E3, 12)
                    else:
                        #reply to host the router's mac
                        r3 = arp()
                        r3.hwtype = a.hwtype
                        r3.prototype = a.prototype
                        r3.hwlen = a.hwlen
                        r3.protolen = a.protolen
                        r3.opcode = arp.REPLY
                        r3.hwdst = a.hwsrc
                        r3.protodst = a.protosrc
                        r3.protosrc = a.protodst
                        r3.hwsrc=EthAddr('00:00:00:00:03:10')
                        
                        e3 = ethernet(type=packet.type, src=r3.hwsrc,dst=a.hwsrc)
                        e3.payload = r3
                        
                        msg3 = of.ofp_packet_out()
                        msg3.data = e3.pack()
                        msg3.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                        msg3.in_port = inport
                        event.connection.send(msg3)
                        
                        msg33 = of.ofp_flow_mod()
                        msg33.match = of.ofp_match()
                        msg33.match.dl_type=0x800
                        msg33.match.nw_dst=a.protosrc
                        msg33.actions.append(of.ofp_action_dl_addr.set_src(r3.hwsrc))
                        msg33.actions.append(of.ofp_action_dl_addr.set_dst(r3.hwdst))
                        msg33.actions.append(of.ofp_action_output(port=inport))
                        self.connection.send(msg33)
            #Deal with ARP REPLY and store ARP cache
            #Prepare to send  buffered ICMP REQUEST packets with new MAC address
            if a.prototype == arp.PROTO_TYPE_IP and a.hwtype == arp.HW_TYPE_ETHERNET and a.opcode == arp.REPLY:
                _arp_cache[IPAddr(a.protosrc)]=EthAddr(a.hwsrc)
                
                msg4 = of.ofp_flow_mod()
                msg4.match = of.ofp_match()
                msg4.match.dl_type=0x800
                msg4.match.nw_dst=a.protosrc
                msg4.actions.append(of.ofp_action_dl_addr.set_src(a.hwdst))
                msg4.actions.append(of.ofp_action_dl_addr.set_dst(a.hwsrc))
                msg4.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg4)
                
                
                self.msg_send (_buff[IPAddr(a.protosrc)],a.hwdst,a.hwsrc,inport)
        '****************************ICMP***********************'
        if packet.find("icmp"):
            _ip_to_port[packet.payload.srcip] = inport
            log.info('IP occurs')
            log.debug('the source IP is %s' %packet.payload.srcip)
            log.debug('the dist IP is %s' %packet.payload.dstip)
            
            #intall the packet and get information of the packet
            #rqt_src: router interface IP addr; rqt_port: router port; rqt_pfx: network prefix; rqt_hwsrc: router interface MAC addr.
            
            payload_bf=packet.payload.payload.payload
            icmp_bf=packet.payload.payload
            
            log.info('icmp type =%s'%packet.payload.payload.type)
            global rqtsrc,rqtdst,rqtport,rqtpfx,rqthwsrc
            global rplsrc,rpldst,rplport,rplpfx,rplhwsrc
            #log.info('icmp cache is %s' %_arp_cache)
            target = 0
            for j in range(0,5):
                for i in range(0,9):
                    if str(_route[i][j])== str(packet.payload.dstip):
                        if j == 0:
                            rqtsrc=_route[i][1]
                            rqtdst=_route[i][0]
                            rqtport=_route[i][2]
                            rqtpfx=_route[i][3]
                            rqthwsrc=_route[i][4]
                            #target = 1 means the icmp packet is to host
                            target = 1
                            break
                        elif j == 1:
                            #router reply to host
                            rplsrc=_route[i][1]
                            rpldst=_route[i][0]
                            rplport=_route[i][2]
                            rplpfx=_route[i][3]
                            rplhwsrc=_route[i][4]
                            #target = 2 means the icmp packet is to router interface
                            target = 2
                            flagd = i
                            break
            for k in range(0,9):
                log.info(_route[k][0])
                if str(_route[k][0])== str(packet.payload.srcip):
                    interfaceip = _route[k][1]
                    interfacedst = _route[k][0]
                    flags = _route[k][2]
                    log.info('flags is %s' %flags)
                    break
            
            '*********ICMP REQUEST***'
            if target == 0:
                self.icmp_unknownhost(packet,interfaceip,inport)
                log.info('unknown from %s' %interfaceip)
            elif packet.payload.payload.type == 8 and target != 0:
                #If we do not have IP_MAC in routing table, create ARP Request
                if packet.payload.dstip not in _arp_cache:
                    _buff[IPAddr(packet.payload.dstip)]=packet
                    _ip_bf[IPAddr(packet.payload.dstip)]=packet.payload
                    if dpid == 1:
                        if rqtport == 1:
                            #r1 broadcast arp request to r2
                            self.arp_request(packet,_arp_cache[_port_to_mac_1['1']],_port_to_mac_1['1'],1)
                        elif rqtport == 2:
                            #r1 broadcast arp request to r3
                            self.arp_request(packet,_arp_cache[_port_to_mac_1['2']],_port_to_mac_1['2'],2)
                        else:
                            self.arp_request(packet,rqtsrc,rqthwsrc,4)
                            self.arp_request(packet,rqtsrc,rqthwsrc,5)
                            self.arp_request(packet,rqtsrc,rqthwsrc,6)
                    elif dpid == 2:
                        if rqtport == 1:
                            #r2 broadcast arp request to r1
                            self.arp_request(packet,_arp_cache[_port_to_mac_2['1']],_port_to_mac_2['1'],1)
                        elif rqtport == 3:
                            #r2 broadcast arp request to r3
                            self.arp_request(packet,_arp_cache[_port_to_mac_2['3']],_port_to_mac_2['3'],3)
                        else:
                            self.arp_request(packet,rqtsrc,rqthwsrc,7)
                            self.arp_request(packet,rqtsrc,rqthwsrc,8)
                            self.arp_request(packet,rqtsrc,rqthwsrc,9)
                    else:
                        if rqtport == 2:
                            #r3 broadcast arp request to r1
                            self.arp_request(packet,_arp_cache[_port_to_mac_3['2']],_port_to_mac_3['2'],2)
                        elif rqtport == 3:
                            #r1 broadcast arp request to r3
                            self.arp_request(packet,_arp_cache[_port_to_mac_3['3']],_port_to_mac_3['3'],3)
                        else:
                            self.arp_request(packet,rqtsrc,rqthwsrc,10)
                            self.arp_request(packet,rqtsrc,rqthwsrc,11)
                            self.arp_request(packet,rqtsrc,rqthwsrc,12)
                #If we have IP_MAC in routing table, forward packet directly 
                elif packet.payload.dstip in _arp_cache:
                    if target == 2:
                        if dpid == 1:
                            #r1 received the request from h4
                            if rplport == 1:
                                #r1 send the request to r2 interface
                                self.msg_send (packet,packet.src,packet.dst,1)
                            elif rplport == 2:
                                #r1 send the request to r3 interface
                                self.msg_send (packet,packet.src,packet.dst,2)
                            else:
                                #r1 reply to h4's request
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,packet.payload.dstip,packet.payload.srcip,rplhwsrc,_arp_cache[packet.payload.srcip],rplport)
                        elif dpid == 2:
                            if inport == 1:
                                #r2 received icmp request from r1 and reply to r1
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,packet.payload.dstip,packet.payload.srcip,_port_to_mac_2[str(inport)],_arp_cache[packet.payload.srcip],inport)
                        else:
                            if inport == 2:
                                #r3 received icmp request from r1 and reply to r1
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,packet.payload.dstip,packet.payload.srcip,_port_to_mac_3[str(inport)],_arp_cache[packet.payload.srcip],inport)
                    elif target == 1:
                        if dpid == 1:
                            if rqtport == 1:
                                #r1 send the request to r2 
                                self.msg_send (packet,_port_to_mac_1['1'],_port_to_mac_2['1'],1)
                            elif rplport == 2:
                                #r1 send the request to r3
                                self.msg_send (packet,_port_to_mac_1['2'],_port_to_mac_3['2'],2)
                            else:
                                #r1 forward the request to h5 or h6(in cache)
                                self.msg_send (packet,rqthwsrc,_arp_cache[rqtdst],rqtport)
                        elif dpid == 2:
                            if rqtport == 1:
                                #r2 send the request to r1
                                self.msg_send (packet,_port_to_mac_2['1'],_port_to_mac_1['1'],1)
                            elif rplport == 3:
                                #r2 send the request to r3
                                self.msg_send (packet,_port_to_mac_2['3'],_port_to_mac_3['3'],3)
                            else:
                                #r2 forward the request to hosts(in cache)
                                self.msg_send (packet,rqthwsrc,_arp_cache[rqtdst],rqtport)
                        else: 
                            if rqtport == 2:
                                #r3 send the request to r1
                                self.msg_send (packet,_port_to_mac_3['2'],_port_to_mac_1['2'],2)
                            elif rplport == 3:
                                #r3 send the request to r2
                                self.msg_send (packet,_port_to_mac_3['3'],_port_to_mac_2['3'],3)
                            else:
                                #r3 forward the request to hosts(in cache)
                                self.msg_send (packet,rqthwsrc,_arp_cache[rqtdst],rqtport)
            ############ICMP REPLY###############
            #Receive ICPM Reply, we need forward the the reply
            elif packet.payload.payload.type == 0:
                if dpid == 1:
                    if rqtport == 1:
                        #r1 send the reply to r2
                        self.msg_send (packet,_port_to_mac_1['1'],_port_to_mac_2['1'],1)
                        
                        msg3 = of.ofp_flow_mod()
                        msg3.match = of.ofp_match()
                        msg3.match.dl_type=0x800
                        msg3.match.nw_dst=packet.payload.dstip
                        msg3.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_1['1']))
                        msg3.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_2['1']))
                        msg3.actions.append(of.ofp_action_output(port=1))
                        log.info('flow mod end 2')
                        self.connection.send(msg3)
                    elif rqtport == 2:
                        #r1 send the reply to r3
                        self.msg_send (packet,_port_to_mac_1['2'],_port_to_mac_3['2'],2)
                        
                        log.info('flow mod starts 2')
                        msg4 = of.ofp_flow_mod()
                        msg4.match = of.ofp_match()
                        msg4.match.dl_type=0x800
                        msg4.match.nw_dst=packet.payload.dstip
                        msg4.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_1['2']))
                        msg4.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_3['2']))
                        msg4.actions.append(of.ofp_action_output(port=2))
                        log.info('flow mod end 2')
                        self.connection.send(msg4)
                    else:
                        #r1 send the reply to h4
                        self.msg_send (packet,rqthwsrc,_arp_cache[packet.payload.dstip],rqtport)
                elif dpid == 2:
                    if rqtport == 1:
                        #r2 send the reply to r1
                        self.msg_send (packet,_port_to_mac_2['1'],_port_to_mac_1['1'],1)
                        
                        log.info('flow mod starts 1')
                        msg0 = of.ofp_flow_mod()
                        msg0.match = of.ofp_match()
                        msg0.match.dl_type=0x800
                        msg0.match.nw_dst=packet.payload.dstip
                        msg0.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_2['1']))
                        msg0.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_1['1']))
                        msg0.actions.append(of.ofp_action_output(port=1))
                        log.info('flow mod ends 1')
                        self.connection.send(msg0)
                    elif rqtport == 3:
                        #r2 send the reply to r3
                        self.msg_send (packet,_port_to_mac_2['3'],_port_to_mac_3['3'],3)
                        
                        log.info('flow mod starts 1')
                        msg0 = of.ofp_flow_mod()
                        msg0.match = of.ofp_match()
                        msg0.match.dl_type=0x800
                        msg0.match.nw_dst=packet.payload.dstip
                        msg0.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_2['3']))
                        msg0.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_3['3']))
                        msg0.actions.append(of.ofp_action_output(port=3))
                        log.info('flow mod ends 1')
                        self.connection.send(msg0)
                    else:
                        #r2 send the reply to hosts
                        self.msg_send (packet,rqthwsrc,_arp_cache[packet.payload.dstip],rqtport)
                else:  
                    if rqtport == 2:
                        #r3 send the reply to r1
                        self.msg_send (packet,_port_to_mac_3['2'],_port_to_mac_1['2'],2)
                        
                        log.info('flow mod starts 1')
                        msg0 = of.ofp_flow_mod()
                        msg0.match = of.ofp_match()
                        msg0.match.dl_type=0x800
                        msg0.match.nw_dst=packet.payload.dstip
                        msg0.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_3['2']))
                        msg0.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_1['2']))
                        msg0.actions.append(of.ofp_action_output(port=2))
                        log.info('flow mod ends 1')
                        self.connection.send(msg0)
                    elif rqtport == 3:
                        #r3 send the reply to r2
                        self.msg_send (packet,_port_to_mac_3['3'],_port_to_mac_2['3'],3)
                        
                        log.info('flow mod starts 1')
                        msg0 = of.ofp_flow_mod()
                        msg0.match = of.ofp_match()
                        msg0.match.dl_type=0x800
                        msg0.match.nw_dst=packet.payload.dstip
                        msg0.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_3['3']))
                        msg0.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_2['3']))
                        msg0.actions.append(of.ofp_action_output(port=3))
                        log.info('flow mod ends 1')
                        self.connection.send(msg0)
                    else:
                        #r3 send the reply to hosts
                        self.msg_send (packet,rqthwsrc,_arp_cache[packet.payload.dstip],rqtport)
        elif packet.find("ipv4"):
            for i in range(0,9):
                if str(_route[i][0])== str(packet.payload.dstip):
                    tcpsrc=_route[i][1]
                    tcpdst=_route[i][0]
                    tcpport=_route[i][2]
                    tcppfx=_route[i][3]
                    tcphwsrc=_route[i][4]
                    break
            if packet.payload.dstip in _arp_cache:
                if dpid == 1:
                    if tcpport == 1:
                        self.msg_send (packet,_port_to_mac_1['1'],_port_to_mac_2['1'],1)
                    elif tcpport == 2:
                        self.msg_send (packet,_port_to_mac_1['2'],_port_to_mac_3['2'],2)
                    else:
                        self.msg_send (packet,tcphwsrc,_arp_cache[tcpdst],tcpport)
                if dpid == 2:
                    if inport == 1:
                        self.msg_send (packet,tcphwsrc,_arp_cache[tcpdst],tcpport)
                    else:
                        self.msg_send (packet,_port_to_mac_2['1'],_port_to_mac_1['1'],1)
            else:
                _buff[IPAddr(packet.payload.dstip)]=packet
                _ip_bf[IPAddr(packet.payload.dstip)]=packet.payload
                if dpid == 1:
                    if tcpport == 1:
                        #r1 broadcast arp request to r2
                        self.arp_request(packet,_arp_cache[_port_to_mac_1['1']],_port_to_mac_1['1'],1)
                    elif tcpport == 2:
                        #r1 broadcast arp request to r3
                        self.arp_request(packet,_arp_cache[_port_to_mac_1['2']],_port_to_mac_1['2'],2)
                    else:
                        self.arp_request(packet,tcpsrc,tcphwsrc,4)
                        self.arp_request(packet,tcpsrc,tcphwsrc,5)
                        self.arp_request(packet,tcpsrc,tcphwsrc,6)
                elif dpid == 2:
                    if tcpport == 1:
                        #r2 broadcast arp request to r1
                        self.arp_request(packet,_arp_cache[_port_to_mac_2['1']],_port_to_mac_2['1'],1)
                    elif tcpport == 3:
                        #r2 broadcast arp request to r3
                        self.arp_request(packet,_arp_cache[_port_to_mac_2['3']],_port_to_mac_2['3'],3)
                    else:
                        self.arp_request(packet,tcpsrc,tcphwsrc,7)
                        self.arp_request(packet,tcpsrc,tcphwsrc,8)
                        self.arp_request(packet,tcpsrc,tcphwsrc,9)
                else:
                    if tcpport == 2:
                        #r3 broadcast arp request to r1
                        self.arp_request(packet,_arp_cache[_port_to_mac_3['2']],_port_to_mac_3['2'],2)
                    elif tcpport == 3:
                        #r3 broadcast arp request to r2
                        self.arp_request(packet,_arp_cache[_port_to_mac_3['3']],_port_to_mac_3['3'],3)
                    else:
                        self.arp_request(packet,tcpsrc,tcphwsrc,10)
                        self.arp_request(packet,tcpsrc,tcphwsrc,11)
                        self.arp_request(packet,tcpsrc,tcphwsrc,12)
'*****************************************************************************'
def launch():
    log.info("*** Starting... ***")
    log.info("*** Waiting for switches to connect.. ***")
    def start_router(event):
        log.debug("Controlling %s" % (event.connection,))
        controller4(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_router)
    log.info('The router is running')
