#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import requests
import xml.etree.ElementTree as et
import pyshark
import csv
#import nest_asyncio

file1 = input("Enter input filename(.pcap):")
file2 = input("Enter output filename(.csv):")


cap = pyshark.FileCapture(file1)
#nest_asyncio.apply()

xml_list = []
packet_list = []
headings = ["frame.encap_type","frame.len","frame.protocols","ip.hdr_len","ip.len",
"ip.flags.rb","ip.flags.df","p.flags.mf","ip.frag_offset","ip.ttl",             "ip.proto","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.len",             "tcp.ack","tcp.flags.res","tcp.flags.ns","tcp.flags.cwr","tcp.flags.ecn",             "tcp.flags.urg","tcp.flags.ack","tcp.flags.push","tcp.flags.reset",             "tcp.flags.syn","tcp.flags.fin","tcp.window_size","tcp.time_delta"]
packet_list.append(headings)

for packet in cap:
  temp = []
  temp.append(str(packet.frame_info._all_fields["frame.encap_type"]) )#0
  temp.append(str(packet.frame_info._all_fields["frame.len"])) #1
  temp.append(str(packet.frame_info._all_fields["frame.protocols"])) #2
  if hasattr(packet, 'ip'):
    temp.append(str(packet.ip._all_fields['ip.hdr_len']))#3
    temp.append(str(packet.ip._all_fields['ip.len']))#4
    temp.append(str(packet.ip._all_fields['ip.flags.rb']))#5
    temp.append(str(packet.ip._all_fields['ip.flags.df']))#6
    temp.append(str(packet.ip._all_fields['ip.flags.mf']))#7
    temp.append(str(packet.ip._all_fields['ip.frag_offset']))#8
    temp.append(str(packet.ip._all_fields['ip.ttl']))#9
    temp.append(str(packet.ip._all_fields['ip.proto']))#10
    temp.append(str(packet.ip._all_fields['ip.src']))#10
    temp.append(str(packet.ip._all_fields['ip.dst']))#11
  else:
    temp.extend(["0","0","0","0","0","0","0","0","0","0"])
  if hasattr(packet, 'tcp'):
    temp.append(str(packet.tcp._all_fields['tcp.srcport']))#12
    temp.append(str(packet.tcp._all_fields['tcp.dstport']))#13
    temp.append(str(packet.tcp._all_fields['tcp.len']))#14
    temp.append(str(packet.tcp._all_fields['tcp.ack']))#15
    temp.append(str(packet.tcp._all_fields['tcp.flags.res']))#16
    temp.append(str(packet.tcp._all_fields['tcp.flags.ns']))#17
    temp.append(str(packet.tcp._all_fields['tcp.flags.cwr']))#18
    temp.append(str(packet.tcp._all_fields['tcp.flags.ecn']))#19
    temp.append(str(packet.tcp._all_fields['tcp.flags.urg']))#20
    temp.append(str(packet.tcp._all_fields['tcp.flags.ack']))#21
    temp.append(str(packet.tcp._all_fields['tcp.flags.push']))#22
    temp.append(str(packet.tcp._all_fields['tcp.flags.reset']))#23
    temp.append(str(packet.tcp._all_fields['tcp.flags.syn']))#24
    temp.append(str(packet.tcp._all_fields['tcp.flags.fin']))#25
    temp.append(str(packet.tcp._all_fields['tcp.window_size']))#26
    #temp.append(packet.tcp._all_fields['tcp.analysis.bytes_in_flight'])
    #temp.append(packet.tcp._all_fields['tcp.analysis.push_bytes_sent'])
    temp.append(str(packet.tcp._all_fields['tcp.time_delta']))#27
  else:
    temp.extend(["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0",])
  packet_list.append(temp)

with open(file2, 'w') as writeFile:
  writer = csv.writer(writeFile)
  writer.writerows(packet_list)

