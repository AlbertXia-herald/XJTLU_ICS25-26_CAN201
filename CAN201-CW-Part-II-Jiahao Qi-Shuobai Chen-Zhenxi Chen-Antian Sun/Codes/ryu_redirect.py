from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, tcp

Server1 = {'ip': '10.0.1.2', 'mac': '00:00:00:00:00:01'}
Server2 = {'ip': '10.0.1.3', 'mac': '00:00:00:00:00:02'}
Client = {'ip': '10.0.1.5', 'mac': '00:00:00:00:00:03'}


class Redirecting(app_manager.RyuApp):
    # OpenFlow Virsion 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Redirecting, self).__init__(*args, **kwargs)
        # initialization of MAC table
        self.mac_to_port = {}

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
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout)
        else:
            # no buffer
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
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

        # redirect Client from Server1 to Server2
        if out_port != ofproto.OFPP_FLOOD:
            # ger ipv4 & tcp pkts
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if ipv4_pkt and tcp_pkt:
                self.logger.info("IPV4: %s \nTCP: %s", ipv4_pkt, tcp_pkt)
                ipv4_src = ipv4_pkt.src
                ipv4_dst = ipv4_pkt.dst

                # redirect tcp connection of Client -> Server1 to Client -> Server2
                if src == Client['mac'] and dst == Server1['mac']:
                    print('TCP Connection: Client -> Server1')
                    if Server2['mac'] in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][Server2['mac']]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ipv4_src,
                        ipv4_dst=ipv4_dst)
                    # change the dst_MAC and dst_IP(Server2)
                    actions = [parser.OFPActionSetField(eth_dst=Server2['mac']),
                               parser.OFPActionSetField(ipv4_dst=Server2['ip']),
                               parser.OFPActionOutput(out_port)]
                # redirect tcp connection of Server2 -> Client to Server1 -> Client
                elif src == Server2['mac'] and dst == Client['mac']:
                    print('TCP Connection: Server2 -> Client')

                    if Client['mac'] in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][Client['mac']]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ipv4_src,
                        ipv4_dst=ipv4_dst)
                    # change the stc_MAC and src_IP(Server1)
                    actions = [parser.OFPActionSetField(eth_src=Server1['mac']),
                               parser.OFPActionSetField(ipv4_src=Server1['ip']),
                               parser.OFPActionOutput(out_port)]
                # normal flow matching
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # not IP/TCP packet, use normal matching
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # install flow entry
            # exist buffer, without the need of send total pkt
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, 5)
            else:
                self.add_flow(datapath, 1, match, actions, None, 5)

        # prepare packet out data
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # send packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data)
        self.logger.info("packet out datapath_id: %s, actions: %s, buffer_id: %s, in_port: %s, out_port: %s", dpid,
                         actions, msg.buffer_id, in_port, out_port)
        datapath.send_msg(out)