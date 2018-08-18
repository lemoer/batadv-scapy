#!/usr/bin/env python3

import argparse
from scapy.all import *
from batadv import *

seen = []

def pkt_callback(pkt):
    assert(BatAdv in pkt)
    global seen

    y = 0

    for ogm in pkt[BatAdv].container:
        if BatAdvOGM not in ogm:
            continue

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
    if y:
        print('.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', metavar='FILE', type=str)

    args = parser.parse_args()

    packets = rdpcap(args.file)
    for pkt in packets:
        pkt_callback(pkt)
