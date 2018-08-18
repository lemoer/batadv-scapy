#!/usr/bin/env python3

import argparse
from scapy.all import *
from batadv import *

seen = []

def pkt_callback(pkt, mac):
    assert(BatAdv in pkt)
    global seen

    y = 0

    for c in pkt[BatAdv].container:
        if BatAdvOGM in c:
            ogm = c

            if ogm.seq in seen:
                continue

            seen += [ogm.seq]


            for tvlv in ogm.tvlvs:
                if BatAdvTvlvTT not in tvlv:
                    continue

                for entry in tvlv.entries:
                    f = entry.flags & 0x03
                    if f == 0:
                        print('ADD!      - orig {} added   {}'.format(ogm.originator, entry.addr))
                    elif f == 1:
                        print('DEL!      - orig {} dropped {}'.format(ogm.originator, entry.addr))
                    elif f == 2:
                        print('ROAM IN!  - orig {} added   {}'.format(ogm.originator, entry.addr))
                    elif f == 3:
                        print('ROAM OUT! - orig {} dropped {}'.format(ogm.originator, entry.addr))
                    y = 1
        elif BatAdvUnicastTvlv in c:
            #TODO: fix
            ogm = c
            if mac is not None and c.dst != mac:
                continue
            for tvlv in c.tvlvs:
                if BatAdvTvlvTT not in tvlv:
                    continue
                tt = tvlv

                if (tt.flags & 0x10) == 0x10:
                    ft = 'FT'
                else:
                    ft = '  '

                for entry in tvlv.entries:
                    f = entry.flags & 0x03
                    if f == 0:
                        print(ft, '2ADD!      - orig {} added   {}'.format(ogm.src, entry.addr))
                    elif f == 1:
                        print(ft, '2DEL!      - orig {} dropped {}'.format(ogm.src, entry.addr))
                    elif f == 2:
                        print(ft, '2ROAM IN!  - orig {} added   {}'.format(ogm.src, entry.addr))
                    elif f == 3:
                        print(ft, '2ROAM OUT! - orig {} dropped {}'.format(ogm.src, entry.addr))
                    y = 1


    if y:
        print('.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', metavar='FILE', type=str)
    parser.add_argument('--filter', metavar='MAC', type=str)

    args = parser.parse_args()

    packets = rdpcap(args.file)
    for pkt in packets:
        pkt_callback(pkt, args.filter)
