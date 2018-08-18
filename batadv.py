#!/usr/bin/env python3

from scapy.packet import *
from scapy.fields import *
from scapy.all import *


BATADV_PACKET_TYPES = {}
BATADV_PACKET_TYPES['IV_OGM'] = 0
BATADV_PACKET_TYPES['UNICAST_TVLV'] = 68

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

class _BatAdvFrameHdr(Packet):
    fields_desc = [
        ByteEnumField('type', 'IV_OGM', BATADV_PACKET_TYPES),
        ByteField('version', 15),
        ByteField('ttl', 64)
    ]


class BatAdvFrame(_FinishedPacket):
    name = 'BATADV TVLV Packet'
    type = BATADV_PACKET_TYPES['IV_OGM']
    fields_desc = [
        _BatAdvFrameHdr,
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

class BatAdvOGM(BatAdvFrame):
    name = 'OGM IV'
    type = BATADV_PACKET_TYPES['IV_OGM']
    fields_desc=[
        _BatAdvFrameHdr,
        FlagsField('flags', 0x00, 8, ['NOT_BEST_NEXT_HOP',
            'PRIMARIES_FIRST_HOP', 'DIRECT_LINK'] + ['']*5),
        IntField('seq', 0),
        MACField('originator', ETHER_ANY),
        MACField('rcvFrom', ETHER_ANY),
        ByteField('pad', 0),
        ByteField('tq', 255),
        FieldLenField('tvlvLen', None, length_of='tvlvs'),
        PacketListField("tvlvs", [], BatAdvTvlv, length_from=lambda p:p.tvlvLen)]

class BatAdvUnicastTvlv(BatAdvFrame):
    name = 'Unicast TVLV'
    type = BATADV_PACKET_TYPES['UNICAST_TVLV']
    fields_desc=[
        _BatAdvFrameHdr,
        ByteField('pad', 0),
        MACField('dst', ETHER_ANY),
        MACField('src', ETHER_ANY),
        BitFieldLenField('tvlvLen', None, 16, length_of='tvlvs'),
        ShortField('pad', 0),
        PacketListField("tvlvs", [], BatAdvTvlv, length_from=lambda p:p.tvlvLen)]

class BatAdv(Packet):
    name = 'BatAdv Packet'
    fields_desc=[
        PacketListField('container', [], BatAdvFrame)
    ]

bind_layers(Ether, BatAdv, type=0x4305)


if __name__ == '__main__':

    packets = rdpcap('test.pcap')

    p = packets[0]
    p2 = packets[1]
    p3 = packets[1]

    print('PACKET 1:')
    print('---------')
    print()

    p.show2()

    print()
    print()
    print('PACKET 2:')
    print('---------')
    print()

    p2.show2()

    print()
    print()
    print('4TH OGM IN PACKET 3:')
    print('--------------------')
    print()

    p3[BatAdv].container[4].show()
