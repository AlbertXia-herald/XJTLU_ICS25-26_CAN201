from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class Forwarding(app_manager.RyuApp):
    # OpenFlow Virsion 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Forwarding, self).__init__(*args, **kwargs)
        # initialization of MAC table
        self.mac_to_port = {}  # format: {dpid: {mac_address: port_number}}

    # Event of Contorller gets Switch_Feature Message
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss entry(default action)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # install flow entry into switch
    # parms: [datapath(switch), priority, match, actions, buffer_id, timeout]
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Improvment1
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            # exist in buffer
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            # no buffer
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    #  Event of Controller Occur Packet In Event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get dpid to determine the sdn_switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received pkts
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        # Improvement2
        # fliter LLDP
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            # fliter STP
        if eth_pkt.ethertype == ether_types.ETH_TYPE_8021Q:
            return
            # just care about normal data pkts
        dst = eth_pkt.dst
        src = eth_pkt.src

        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # self-learn to avoid next time flooding
        self.mac_to_port[dpid][src] = in_port

        # decide the pkt flooding or not
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            # pkt has be buffered,no need of send
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, 5)
            else:
                self.add_flow(datapath, 1, match, actions, None, 5)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        self.logger.info("packet out datapath_id: %s, actions: %s, buffer_id: %s, in_port: %s", dpid, actions,
                         msg.buffer_id, in_port)
        datapath.send_msg(out)