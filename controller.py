import eventlet
eventlet.monkey_patch()

from os_ken.base.app_manager import OSKenApp
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, tcp, ipv4
import logging
import subprocess
import random

class Controller(OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('MaliciousTraffic')
        self.syn_count_file = "syn_count.txt"
        with open(self.syn_count_file, 'w') as f:
            f.write('0')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.__add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # If it's normal traffic, just forward...
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]

        if tcp_pkt and ip_pkt:
            # Only redirect if it's a SYN packet [0x02]
            if tcp_pkt.bits == 0x02:
                self.logger.info(f"MALICIOUS SYN: {ip_pkt.src} -> Triggering Honeypot Redirection")
                self.increment_syn_counter()
                self.install_flow(datapath, in_port, ip_pkt.src, ip_pkt.dst)
                
                # Change current packet action to normal output to stop it from getting stuck
                actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions,
            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def increment_syn_counter(self):
        try:
            with open(self.syn_count_file, 'r+') as f:
                val = f.read().strip()
                count = int(val) if val else 0
                f.seek(0); f.write(str(count + 1)); f.truncate()
        except Exception: pass

    def install_flow(self, datapath, in_port, src_ip, dst_ip):
        try:
            cmd = "docker ps -q | wc -l"
            output = subprocess.check_output(cmd, shell=True)
            pool_size = int(output.decode().strip())
        except Exception: pool_size = 0

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip)

        if pool_size > 0:
            # Selection logic
            target_hp_ip = f"172.17.0.{random.randint(0, pool_size - 1) + 2}"
            actions = [
                parser.OFPActionSetField(ipv4_dst=target_hp_ip),
                parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)
            ]
            self.logger.info(f"RULE INSTALLED: {src_ip} redirected to {target_hp_ip}")
        else:
            actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]

        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Priority 100 to make sure it overrides default flooding rule
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, 
                                instructions=inst, idle_timeout=20)
        datapath.send_msg(mod)

    def __add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)