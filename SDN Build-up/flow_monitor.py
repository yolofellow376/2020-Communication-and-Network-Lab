# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
check=[]
flag=0
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath={}
        self.monitor_thread=hub.spawn(self._monitor)
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER,DEAD_DISPATCHER])
    def _state_change_handler(self,ev):
        datapath=ev.datapath
        if ev.state==MAIN_DISPATCHER:
           if not datapath.id in self.datapath:
              self.datapath[datapath.id]=datapath
        elif ev.state== DEAD_DISPATCHER:
           if datapath.id in self.datapath:
              del self.datapath[datapath.id]
    def _monitor(self):
        while True:
            for dp in self.datapath.values():
                #self._request_stats(dp)
                self._request_flow(dp)
            hub.sleep(1)
    def _request_stats(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        req=parser.OFPPortStatsRequest(datapath,0,ofproto.OFPP_ANY)
        datapath.send_msg(req)
    def _request_flow(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        req=parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    #@set_ev_cls(ofp_event.EventOFPPortStatsReply,MAIN_DISPATCHER)
    def _port_stats_reply_handler(self,ev):
        body=ev.msg.body
        for i in self.mac_to_port:
            print('-------------------------------')
            print('SW_ID: '+str(int(i)))
            #for stat in sorted(body,key=attrgetter('port_no')):
            for stat in body:
                print('port: '+str(stat.port_no))
                print('tx_packets: '+str(stat.tx_packets))
                print('rx_packets: '+str(stat.rx_packets)+'\n')            
            print('Address            Port\n')
            for j in self.mac_to_port[i]:
                print(str(j)+"    "+str(self.mac_to_port[i][j]))
            print('-------------------------------')

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply,MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self,ev):
        body=ev.msg.body
        datapath=ev.msg.datapath
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            #print(stat)
            match=stat.match
            #print(stat.packet_count)
            #print(match)
            if stat.packet_count>5:
                #print('delete this:'+str(match['eth_src']))
                self.del_flow(datapath,stat.match,stat.instructions)
                #print(match['eth_src'])
                string=match['eth_src']+match['eth_dst']
                if string not in check:
                    check.append(string)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    def del_flow(self,datapath,match,inst):
        ofproto= datapath.ofproto
        parser =datapath.ofproto_parser
        mod = parser.OFPFlowMod(
              datapath=datapath,
              command=ofproto.OFPFC_DELETE,out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY,match=match,instructions=inst)
        datapath.send_msg(mod)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch      
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        #print('new:'+src)
        string = src+dst
        if string in check:
           print('found')
           return    
      
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
