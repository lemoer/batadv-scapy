#!/usr/bin/env python3

from scapy.packet import *
from scapy.fields import *
from scapy.all import *


BATADV_PACKET_TYPES = {}
BATADV_PACKET_TYPES['IV_OGM'] = 0

BATADV_TVLV_TYPES = {}
BATADV_TVLV_TYPES['DAT'] = 0x02
BATADV_TVLV_TYPES['TT'] = 0x04
BATADV_TVLV_TYPES['Multicast'] = 0x06

# TODO: remove "pad" field
# TODO: types?
# TODO: ukn field?

class _FinishedPacket(Packet):
    # contains no payload
    def extract_padding(self, p):
        return b"", p

class _BatAdvTvlvHDR(Packet):
    fields_desc = [
        ByteEnumField('type', None, BATADV_TVLV_TYPES), 
        ByteField('version', 0x01),
        FieldLenField('length', None, length_of="value")]
   

class BatAdvTvlv(_FinishedPacket):
    name = 'BATADV TVLV Packet'
    fields_desc = [
        _BatAdvTvlvHDR,
        StrLenField("value", "", length_from=lambda pkt:pkt.length)]

    registered_ip_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_ip_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            opt = orb(pkt[0])
            if opt in cls.registered_ip_options:
                return cls.registered_ip_options[opt]
        return cls

class BatAdvTvlvTTVLAN(_FinishedPacket):
    name = 'TT VLAN'
    fields_desc = [
        XIntField('crc', 0),
        XShortField('vid', 0),
        XShortField('ukn', 0)
    ]

class BatadvTvlvTTEntry(_FinishedPacket):
    name = 'TT Entry'
    fields_desc=[
        FlagsField('flags', 0x0, 8, 'DRUUWIUU'), # U means unused
        BitField('pad', 0, 24),
        MACField('addr', ETHER_ANY),
        XShortField('vid', 0)
    ]

class BatAdvTvlvTT(BatAdvTvlv):
    name = 'TT Container'
    type = BATADV_TVLV_TYPES['TT']
    fields_desc = [
        _BatAdvTvlvHDR,
        FlagsField('flags', 0, 8, ['QT_DIFF','','','','FT','','','']),
        ByteField('ttvn', 0),
        BitFieldLenField('vlanCount', None, 16, count_of='vlans'),
        PacketListField('vlans', [], BatAdvTvlvTTVLAN,
            count_from=lambda pkt: pkt.vlanCount),
        PacketListField('entries', [], BatadvTvlvTTEntry,
            length_from=lambda pkt: pkt.length-pkt.vlanCount*8-4)
        ]

class BatAdvOGM(_FinishedPacket):
    name = 'OGM'
    fields_desc=[
        ByteEnumField('type', 'IV_OGM', BATADV_PACKET_TYPES),
        ByteField('version', 15),
        ByteField('ttl', 64),
        FlagsField('flags', 0x00, 8, ['NOT_BEST_NEXT_HOP',
            'PRIMARIES_FIRST_HOP', 'DIRECT_LINK'] + ['']*5),
        IntField('seq', 0),
        MACField('originator', ETHER_ANY),
        MACField('rcvFrom', ETHER_ANY),
        ByteField('pad', 0),
        ByteField('tq', 255),
        FieldLenField('tvlvLen', None, length_of='tvlvs'),
        PacketListField("tvlvs", [], BatAdvTvlv, length_from=lambda p:p.tvlvLen)]

class BatAdv(Packet):
    name = 'BatAdv Packet'
    fields_desc=[
        PacketListField('container', [], BatAdvOGM)
    ]


bind_layers(Ether, BatAdv, type=0x4305)

packets = rdpcap('test.pcap')
packets2 = rdpcap('test2.pcap')

p = packets[0]
p2 = packets2[0]

p.show2()


p2[BatAdv].container[4].show()
