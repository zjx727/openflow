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

_arp_cache = {IPAddr('10.0.1.1'):EthAddr('00:00:00:00:00:04'),IPAddr('10.0.2.1'):EthAddr('00:00:00:00:00:07'),'1':EthAddr('00:00:00:00:00:05'),'2':EthAddr('00:00:00:00:00:06'),EthAddr('00:00:00:00:00:05'):IPAddr('10.0.3.1'),EthAddr('00:00:00:00:00:06'):IPAddr('10.0.3.2'),EthAddr('00:00:00:00:00:04'):IPAddr('10.0.1.1'),EthAddr('00:00:00:00:00:07'):IPAddr('10.0.2.1')}
_route1=([(IPAddr('10.0.1.2'),IPAddr('10.0.1.1'),2,'10.0.1.0/24',EthAddr('00:00:00:00:00:04')),(IPAddr('10.0.1.3'),IPAddr('10.0.1.1'),3,'10.0.1.0/24',EthAddr('00:00:00:00:00:04')),(IPAddr('10.0.2.2'),IPAddr('10.0.2.1'),1,'10.0.2.0/24',EthAddr('00:00:00:00:00:05'))])
_route2=([(IPAddr('10.0.1.2'),IPAddr('10.0.1.1'),1,'10.0.1.0/24',EthAddr('00:00:00:00:00:06')),(IPAddr('10.0.1.3'),IPAddr('10.0.1.1'),1,'10.0.1.0/24',EthAddr('00:00:00:00:00:06')),(IPAddr('10.0.2.2'),IPAddr('10.0.2.1'),2,'10.0.2.0/24',EthAddr('00:00:00:00:00:07'))])
_port_to_mac_1 = {'1':EthAddr('00:00:00:00:00:05'),'2':EthAddr('00:00:00:00:00:04'),'3':EthAddr('00:00:00:00:00:04')}
_port_to_mac_2 = {'1':EthAddr('00:00:00:00:00:06'),'2':EthAddr('00:00:00:00:00:07')}
_ip_to_port = {}
rqtsrc,rqtdst,rqtport,rqtpfx,rqthwsrc=0,0,0,0,0
rplsrc,rpldst,rplport,rplpfx,rplhwsrc=0,0,0,0,0
icmpf=icmp()
ip_pakt = ipv4()
eth = ethernet()
_buff={}
_ip_bf={}

class controller3 (object):
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
        #log.info('dpid is %s ' %dpid)
        packet = event.parsed # This is the parsed packet data.
        inport = event.port
        if not packet.parsed:
            log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return
        packet_in = event.ofp # The actual ofp_packet_in message.

        #log.info("Installing flow...")
        # Maybe the log statement should have source/destination/port?
        #log.debug('the source MAC is %s' %packet.src)
        #log.debug('the dist MAC is %s' %packet.dst)
        #log.debug('the source port is %s' %packet_in.in_port)
        if dpid == 1:
            _route = _route1
        else:
            _route = _route2
        '***********************ARP**********************************'
        if packet.find("arp"):
            a= packet.find('arp')
            if not a : return
            log.debug("ARP %s %s => %s",{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
            _ip_to_port[IPAddr(a.protosrc)]=inport
            
            #Deal with ARP REQUEST then ARP REPLY to hosts
            if a.prototype == arp.PROTO_TYPE_IP and a.hwtype == arp.HW_TYPE_ETHERNET and a.opcode == arp.REQUEST:
                _arp_cache[IPAddr(a.protosrc)]=EthAddr(a.hwsrc)
                #log.info('store to cache %s' %_arp_cache)
                #log.info('self._arp_cache[a.protosrc] = %s protosrc is %s' %(self._arp_cache[IPAddr(a.protosrc)],IPAddr(a.protosrc)))
                
                if dpid == 2 and inport == 1:
                    p =arp()
                    p.hwtype = arp.HW_TYPE_ETHERNET
                    p.prototype = arp.PROTO_TYPE_IP
                    p.hwlen = 6
                    p.protolen = 4
                    p.opcode = arp.REQUEST
                    p.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
                    p.hwsrc = EthAddr('00:00:00:00:00:07')
                    p.protodst = _route[2][0]
                    p.protosrc = _route[2][1]
        
                    E = ethernet(type=ethernet.ARP_TYPE, src=p.hwsrc,dst=p.hwdst)
                    E.payload = p
                    self.resend_packet (E, 2)
                elif dpid == 1 and inport == 1:
                    pp =arp()
                    pp.hwtype = arp.HW_TYPE_ETHERNET
                    pp.prototype = arp.PROTO_TYPE_IP
                    pp.hwlen = 6
                    pp.protolen = 4
                    pp.opcode = arp.REQUEST
                    pp.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
                    pp.hwsrc = EthAddr('00:00:00:00:00:04')
                    pp.protodst = a.protodst
                    pp.protosrc = IPAddr('10.0.1.1')
        
                    EE = ethernet(type=ethernet.ARP_TYPE, src=pp.hwsrc,dst=pp.hwdst)
                    EE.payload = pp
                        
                    self.resend_packet (EE, 2)
                    self.resend_packet (EE, 3)
                else:
                    r = arp()
                    r.hwtype = a.hwtype
                    r.prototype = a.prototype
                    r.hwlen = a.hwlen
                    r.protolen = a.protolen
                    r.opcode = arp.REPLY
                    r.hwdst = a.hwsrc
                    r.protodst = a.protosrc
                    r.protosrc = a.protodst
                    if str(a.protodst)=='10.0.1.1':
                        r.hwsrc=EthAddr('00:00:00:00:00:04')
                    if str(a.protodst)=='10.0.2.1':
                        r.hwsrc=EthAddr('00:00:00:00:00:07')
    
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

            #Deal with ARP REPLY and store ARP cache
            #Prepare to send  buffered ICMP REQUEST packets with new MAC address
            if a.prototype == arp.PROTO_TYPE_IP and a.hwtype == arp.HW_TYPE_ETHERNET and a.opcode == arp.REPLY:
                _arp_cache[IPAddr(a.protosrc)]=EthAddr(a.hwsrc)
                
                msg2 = of.ofp_flow_mod()
                msg2.match = of.ofp_match()
                msg2.match.dl_type=0x800
                msg2.match.nw_dst=a.protosrc
                msg2.actions.append(of.ofp_action_dl_addr.set_src(a.hwdst))
                msg2.actions.append(of.ofp_action_dl_addr.set_dst(a.hwsrc))
                msg2.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg2)
                
                
                self.msg_send (_buff[IPAddr(a.protosrc)],a.hwdst,a.hwsrc,inport)
                #self.icmp_forward(_buff[IPAddr(a.protosrc)],TYPE_ECHO_REQUEST,_ip_bf[IPAddr(a.protosrc)].srcip,_ip_bf[IPAddr(a.protosrc)].dstip,a.hwdst,a.hwsrc,inport)
                log.info('forward dic %s' %_buff[IPAddr(a.protosrc)])
        '****************************ICMP***********************'
        if packet.find("icmp"):
            log.info('ICMP occurs')
            _ip_to_port[IPAddr(packet.payload.srcip)]=inport

            #intall the packet and get information of the packet
            #rqt_src: router interface IP addr; rqt_port: router port; rqt_pfx: network prefix; rqt_hwsrc: router interface MAC addr.
            
            payload_bf=packet.payload.payload.payload
            icmp_bf=packet.payload.payload
            
            #log.info('icmp type =%s'%packet.payload.payload.type)
            global rqtsrc,rqtdst,rqtport,rqtpfx,rqthwsrc
            global rplsrc,rpldst,rplport,rplpfx,rplhwsrc
            #log.debug('before loop:')
            #log.info('icmp cache is %s' %_arp_cache)
            target = 0
            for j in range(0,5):
                for i in range(0,3):
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
            for k in range(0,3):
                if str(_route[k][0])== str(packet.payload.srcip):
                    interfaceip = _route[k][1]
                    interfacedst = _route[k][0]
                    flags = _route[k][2]
                    break
            
            '*********ICMP REQUEST***'
            if target == 0:
                log.info('unknown')
                self.icmp_unknownhost(packet,interfaceip,inport)
                log.info('unknown from %s' %interfaceip)
                
            elif packet.payload.payload.type == 8 and target != 0:
                #If we do not have IP_MAC in routing table, create ARP Request
                if packet.payload.dstip not in _arp_cache:
                    self.arp_request(packet,_arp_cache[rqthwsrc],rqthwsrc,rqtport)
                    _buff[IPAddr(packet.payload.dstip)]=packet
                    _ip_bf[IPAddr(packet.payload.dstip)]=packet.payload
                    #log.info('buff %s' %_buff)
                #If we have IP_MAC in routing table, forward packet directly 
                elif packet.payload.dstip in _arp_cache:
                    if target == 1:
                        if dpid == 1:
                            if rqtport != 1:
                                #h3 ICMP request forward to h4
                                self.icmp_forward(packet.payload.payload.payload,TYPE_ECHO_REQUEST,packet.payload.srcip,packet.payload.dstip,rqthwsrc,_arp_cache[IPAddr(packet.payload.dstip)],rqtport)
                            else:
                                #s1 ICMP request forward to s2
                                self.msg_send (packet,packet.src,packet.dst,1)
                        else:
                            if inport == 1:
                                #s2 have to forward it to h5
                                self.icmp_forward(packet.payload.payload.payload,TYPE_ECHO_REQUEST,packet.payload.srcip,packet.payload.dstip,_arp_cache[rqtsrc],_arp_cache[IPAddr(packet.payload.dstip)],rqtport)
                            else:
                                #s2 give it to s1
                                self.msg_send (packet,packet.src,packet.dst,1)
                    elif target == 2:
                        #log.debug('icmp cache %s' %_arp_cache)
                        #log.info('flags is %s' %flags)
                        #log.info('dpid is %s, rplport is %s, dstinterface is %s' %(dpid, rplport,interfaceip))
                        if dpid == 1:
                            if rplport !=  inport:
                                #ping other gateway
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,rplsrc,interfacedst,packet.dst,packet.src,inport)
                            else:
                                #ping default gateway
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,rplsrc,rpldst,rplhwsrc,_arp_cache[IPAddr(rpldst)],rplport)
                        else:
                            if flags ==  flagd:
                                #ping default gateway
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,rplsrc,rpldst,rplhwsrc,_arp_cache[IPAddr(rpldst)],rplport)
                            else:
                                #ping other gateway
                                self.icmp_forward(payload_bf,TYPE_ECHO_REPLY,interfaceip,interfacedst,packet.dst,packet.src,inport)
            ############ICMP REPLY###############
            #Receive ICPM Reply, we need forward the the reply
            elif packet.payload.payload.type == 0:
                if dpid == 2:
                    #h5 reply to h3
                    if inport == 2:
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
                        
                        self.msg_send (packet,packet.src,packet.dst,1)
                    else:
                        self.msg_send (packet,rqthwsrc,_arp_cache[packet.payload.dstip],rqtport)
                elif dpid == 1 and rqtport != 1:
                    #h3 and h4 want to receive
                    if inport != 1:
                        self.icmp_forward(packet.payload.payload.payload,TYPE_ECHO_REPLY,packet.payload.srcip,packet.payload.dstip,rqthwsrc,_arp_cache[IPAddr(packet.payload.dstip)],rqtport)
                    else:
                        self.msg_send (packet,rqthwsrc,_arp_cache[packet.payload.dstip],rqtport)
                else:
                    log.info('flow mod starts 2')
                    msg3 = of.ofp_flow_mod()
                    msg3.match = of.ofp_match()
                    msg3.match.dl_type=0x800
                    msg3.match.nw_dst=packet.payload.dstip
                    msg3.actions.append(of.ofp_action_dl_addr.set_src(_port_to_mac_1['1']))
                    msg3.actions.append(of.ofp_action_dl_addr.set_dst(_port_to_mac_2['1']))
                    msg3.actions.append(of.ofp_action_output(port=1))
                    log.info('flow mod end 2')
                    self.connection.send(msg3)
                    
                    self.msg_send (packet,packet.src,packet.dst,1)
                    #log.info('ICMP reply for h5 from s1 to s2')
        #########TCP+UDP############
        elif packet.find("ipv4"):
            log.info('TCP occurs')
            for i in range(0,3):
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
                        #s1 send the request to s2
                        self.msg_send (packet,_port_to_mac_1['1'],_port_to_mac_2['1'],1)
                    else:
                        #s1 send the request to h4
                        self.msg_send (packet,tcphwsrc,_arp_cache[tcpdst],tcpport)
                else:
                    #s2 received a request
                    if inport == 1:
                        #s2 send the request to h5
                        self.msg_send (packet,tcphwsrc,_arp_cache[tcpdst],tcpport)
                    else:
                        #s2 send to s1
                        self.msg_send (packet,_port_to_mac_2['1'],_port_to_mac_1['1'],1)
            else:
                #not in cache
                _buff[IPAddr(packet.payload.dstip)]=packet
                if dpid == 1:
                    if tcpport == 1:
                        #s1 send the arp request to s2
                        self.arp_request(packet,_arp_cache[_port_to_mac_1['1']],_port_to_mac_1['1'],1)
                    else:
                        #s1 broadcast arp request
                        self.arp_request(packet,tcpsrc,tcphwsrc,2)
                        self.arp_request(packet,tcpsrc,tcphwsrc,3)
                else:
                    #s2 send the arp request to s1
                    self.arp_request(packet,_arp_cache[_port_to_mac_2['1']],_port_to_mac_2['1'],1)
'*****************************************************************************'
def launch():
    log.info("*** Starting... ***")
    log.info("*** Waiting for switches to connect.. ***")
    def start_router(event):
        log.debug("Controlling %s" % (event.connection,))
        controller3(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_router)
    log.info('The router is running')