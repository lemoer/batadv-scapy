# batadv-scapy

- Some very basic experiments to parse OGM in scapy

```
lemoer@orange ~/d/f/g/batadv-scapy> python batadv.py >> README.md
PACKET 1:
---------

###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 88:e6:40:20:a0:01
  type      = 0x4305
###[ BatAdv Packet ]###
     \container \
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 48
      |  flags     = 
      |  seq       = 984059959
      |  originator= fa:d9:45:8d:77:5b
      |  rcvFrom   = 88:e6:40:20:90:01
      |  pad       = 0
      |  tq        = 176
      |  tvlvLen   = 28
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 12
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 120
      |   |  vlanCount = 1
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0xfbe4f6a0
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x0
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 48
      |  flags     = 
      |  seq       = 248514467
      |  originator= 06:95:ee:8f:50:a3
      |  rcvFrom   = 88:e6:40:20:90:01
      |  pad       = 0
      |  tq        = 185
      |  tvlvLen   = 36
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 20
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 165
      |   |  vlanCount = 2
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0xf54e602f
      |   |   |  vid       = 0x8000
      |   |   |  ukn       = 0x0
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x8a956d33
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0xba00
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 47
      |  flags     = 
      |  seq       = 3292090887
      |  originator= f2:ec:fa:7f:6d:a3
      |  rcvFrom   = 88:e6:40:20:90:01
      |  pad       = 0
      |  tq        = 145
      |  tvlvLen   = 28
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 12
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 231
      |   |  vlanCount = 1
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x66606ee2
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x0
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 48
      |  flags     = 
      |  seq       = 103988449
      |  originator= 86:6e:4f:d6:1c:23
      |  rcvFrom   = 88:e6:40:20:90:01
      |  pad       = 0
      |  tq        = 181
      |  tvlvLen   = 36
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 20
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 193
      |   |  vlanCount = 2
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x6b6719bc
      |   |   |  vid       = 0x8000
      |   |   |  ukn       = 0x0
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x56171f2a
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x8774
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 47
      |  flags     = 
      |  seq       = 1300142035
      |  originator= 22:cf:04:50:1e:db
      |  rcvFrom   = 88:e6:40:20:90:01
      |  pad       = 0
      |  tq        = 145
      |  tvlvLen   = 108
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 92
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 184
      |   |  vlanCount = 2
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x608446b0
      |   |   |  vid       = 0x8000
      |   |   |  ukn       = 0x0
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x594715d2
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x0
      |   |  \entries   \
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = W
      |   |   |  pad       = 0
      |   |   |  addr      = 60:d9:c7:0a:c4:2e
      |   |   |  vid       = 0x0
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = 
      |   |   |  pad       = 0
      |   |   |  addr      = 33:33:00:00:00:fb
      |   |   |  vid       = 0x0
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = 
      |   |   |  pad       = 0
      |   |   |  addr      = 33:33:ff:4f:9c:f7
      |   |   |  vid       = 0x0
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = 
      |   |   |  pad       = 0
      |   |   |  addr      = 33:33:ff:d1:57:f0
      |   |   |  vid       = 0x0
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = 
      |   |   |  pad       = 0
      |   |   |  addr      = 33:33:ff:16:98:3f
      |   |   |  vid       = 0x0
      |   |   |###[ TT Entry ]###
      |   |   |  flags     = 
      |   |   |  pad       = 0
      |   |   |  addr      = 33:33:ff:32:34:92
      |   |   |  vid       = 0x0
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 48
      |  flags     = 
      |  seq       = 764224309
      |  originator= 02:8f:42:42:1c:eb
      |  rcvFrom   = 88:e6:40:20:50:01
      |  pad       = 0
      |  tq        = 53
      |  tvlvLen   = 36
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 20
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 142
      |   |  vlanCount = 2
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0xb5b527b
      |   |   |  vid       = 0x8000
      |   |   |  ukn       = 0x0
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0xce93f3f0
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x7171
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''
      |###[ OGM ]###
      |  type      = IV_OGM
      |  version   = 15
      |  ttl       = 48
      |  flags     = 
      |  seq       = 3293218053
      |  originator= 1a:f2:9d:fb:5a:5b
      |  rcvFrom   = 88:e6:40:20:50:01
      |  pad       = 0
      |  tq        = 63
      |  tvlvLen   = 36
      |  \tvlvs     \
      |   |###[ TT Container ]###
      |   |  type      = TT
      |   |  version   = 1
      |   |  length    = 20
      |   |  flags     = QT_DIFF
      |   |  ttvn      = 9
      |   |  vlanCount = 2
      |   |  \vlans     \
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0xa899d0fb
      |   |   |  vid       = 0x8000
      |   |   |  ukn       = 0x0
      |   |   |###[ TT VLAN ]###
      |   |   |  crc       = 0x66a4df3b
      |   |   |  vid       = 0x0
      |   |   |  ukn       = 0x0
      |   |  \entries   \
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = Multicast
      |   |  version   = 2
      |   |  length    = 4
      |   |  value     = '\x01\x00\x00\x00'
      |   |###[ BATADV TVLV Packet ]###
      |   |  type      = DAT
      |   |  version   = 1
      |   |  length    = 0
      |   |  value     = ''


4TH OGM IN PACKET 2:
--------------------

###[ OGM ]###
  type      = IV_OGM
  version   = 15
  ttl       = 46
  flags     = 
  seq       = 1587077377
  originator= be:9b:6d:9d:f9:33
  rcvFrom   = 88:e6:40:20:20:01
  pad       = 0
  tq        = 66
  tvlvLen   = 36
  \tvlvs     \
   |###[ TT Container ]###
   |  type      = TT
   |  version   = 1
   |  length    = 20
   |  flags     = QT_DIFF
   |  ttvn      = 44
   |  vlanCount = 2
   |  \vlans     \
   |   |###[ TT VLAN ]###
   |   |  crc       = 0xeac42a4e
   |   |  vid       = 0x8000
   |   |  ukn       = 0x0
   |   |###[ TT VLAN ]###
   |   |  crc       = 0xdaa5cc27
   |   |  vid       = 0x0
   |   |  ukn       = 0x0
   |  \entries   \
   |###[ BATADV TVLV Packet ]###
   |  type      = Multicast
   |  version   = 2
   |  length    = 4
   |  value     = '\x01\x00\x00\x00'
   |###[ BATADV TVLV Packet ]###
   |  type      = DAT
   |  version   = 1
   |  length    = 0
   |  value     = ''
```
