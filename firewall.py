from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Tutorial (object):
    def __init__ (self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.mac_to_port = {}

    def resend_packet (self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        self.connection.send(msg)


    def act_like_switch (self, packet, packet_in):
        self.mac_to_port[packet.src] =packet_in.in_port
        log.debug('get mac')
        
        if packet.type != 0x0800:
            if packet.dst in self.mac_to_port:
                self.resend_packet(packet_in,self.mac_to_port[packet.dst])
                log.debug('resend match')
                  
                log.debug("Installing flow...")
                log.debug('the source MAC is %s' %packet.src)
                log.debug('the dist MAC is %s' %packet.dst)
                
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout=60   #50
                msg.hard_timeout= 600    #1000
                msg.match.dl_type = 0x0800
                msg.match.dl_dst=packet.dst
                action = of.ofp_action_output(port=self.mac_to_port[packet.dst])
                msg.actions.append(of.ofp_action_output(port = self.mac_to_port[packet.dst]))
                self.connection.send(msg)
            else:
                self.resend_packet(packet_in, of.OFPP_ALL)
        else:
            if packet.dst in self.mac_to_port:
                log.info('type %s' %packet.nw_proto)
                if packet.nw_proto == 6:
                    log.info("Ignoring tcp packet")
                    return
                elif packet.nw_proto != 6:
                    self.resend_packet(packet_in,self.mac_to_port[packet.dst])
                    log.debug('resend match')
                      
                    log.debug("Installing flow...")
                    log.debug('the source MAC is %s' %packet.src)
                    log.debug('the dist MAC is %s' %packet.dst)
                    
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match.from_packet(packet)
                    msg.idle_timeout=60   #50
                    msg.hard_timeout= 600    #1000
                    msg.match.dl_type = 0x0800
                    msg.match.dl_dst=packet.dst
                    action = of.ofp_action_output(port=self.mac_to_port[packet.dst])
                    msg.actions.append(of.ofp_action_output(port = self.mac_to_port[packet.dst]))
                    self.connection.send(msg)
                else:
                    self.resend_packet(packet_in, of.OFPP_ALL)
                    
    def _handle_PacketIn (self, event):
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        packet_in = event.ofp # The actual ofp_packet_in message.
        self.act_like_switch(packet, packet_in)
        
def launch ():
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)