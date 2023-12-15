from __future__ import print_function

import warnings
warnings.filterwarnings('ignore', message='.*cryptography', )
warnings.filterwarnings('ignore', message='.*oracledb', )
import oracledb

from scapy.all import *
import time
import argparse

class TelemetryReport_v10(Packet):

    name = "INT telemetry report v1.0"

    # default value a for telemetry report with INT
    fields_desc = [
        BitField("ver" , 1 , 4),
        BitField("len" , 1 , 4),
        BitField("nProto", 0, 3),
        BitField("repMdBits", 0, 6),
        BitField("reserved", None, 6),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 1, 1),
        BitField("hw_id", None, 6),

        IntField("swid", None),
        IntField("seqNumber", None),
        IntField("ingressTimestamp", None) ]

class INT_v10(Packet):

    name = "INT v1.0"

    fields_desc = [
        XByteField("type", 1),
        XByteField("shimRsvd1", None),
        XByteField("length", None),
        BitField("dscp", None, 6),
        BitField("shimRsvd2", None, 2),

        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1),
        BitField("rsvd1", 0, 7),
        BitField("rsvd2", 0, 3),
        BitField("hopMLen", None, 5),
        XByteField("remainHopCnt", None),

        XShortField("ins", None),
        XShortField("res", 0),

        FieldListField("INTMetadata", [], XIntField("", None), count_from=lambda p:p.length - 2)
        ]

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='INT Telemetry Report pkt gen.')
    parser.add_argument("-t5", "--test_event_detection", action='store_true',
        help="Test out of interval")
    parser.add_argument("-t7", "--test_event_correctness", action='store_true',
        help="Test the correctness of event detection")
    parser.add_argument("-t8", "--test_v10_spec", action='store_true',
        help="Test v1.0 spec implementation")
    args = parser.parse_args()

    # p_3sw_8d = []
    # p_6sw_8d = []
    # p_6sw_f_id = []
    # tcp_p_3sw_8d = []


    # test event_detection
    if args.test_event_detection:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 5<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1],
                originDSCP=14)

        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 5<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1000,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1],
                originDSCP=14)

        iface = "veth_0"

        try:
            while 1:
                sendp(p0, iface=iface)
                time.sleep(5)
                sendp(p1, iface=iface)
                time.sleep(5)

        except KeyboardInterrupt:
            pass

  
    # test event_detection
    if args.test_event_correctness:
        p = []
        n_sw = 3
        lats = [200, 202, 196, 223, 212, 215, 198, 218, 186, 186, 202, 186, 202, 221, 185, 225, 186, 269, 211, 196, 252, 239, 193, 209, 235, 192, 756, 465, 488, 484, 490, 452, 438, 483, 448, 439, 439, 465, 458, 351, 249, 213, 249, 213, 186, 187, 199, 245, 206, 199, 225, 398, 233, 300, 241, 205, 199, 248, 215, 234, 226, 239, 193, 193, 185, 203, 186, 190, 185, 184, 246, 218, 182, 234, 229, 249, 209, 247, 250, 195, 201, 239, 222, 234, 272, 247, 213, 171, 182, 239, 174, 832, 224, 234, 238, 230, 238, 192, 222, 232]

        for i, lat in enumerate(lats):
            INTdata = [4, 40, (i+1)*1e6, 5, 41, (i+1)*1e6, 6, lat, (i+1)*1e6]
            p.append(Ether()/ \
                        IP(tos=0x17<<2)/ \
                        UDP(sport=5000, dport=54321)/ \
                        TelemetryReport(ingressTimestamp= 1524138290)/ \
                        Ether()/ \
                        IP(src="10.0.0.1", dst="10.0.0.2")/ \
                        UDP(sport=5000, dport=5000)/ \
                        INT(insCnt=3, totalHopCnt=n_sw, ins=(1<<7|1<<5|1<<2)<<8,
                            INTMetadata= INTdata,
                            originDSCP=14))


        iface = "vtap0"

        for p0 in p:
            sendp(p0, iface=iface)
            time.sleep(1)


        # wrpcap("pcaps/t7.pcap", p)
        # print("Done: t7.pcap")


    # test v1.0 spec impelementation
    if args.test_v10_spec:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=27, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
            )

        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=27, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1000,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
            )

        iface = "veth_0"

        try:
            while 1:
                sendp(p0, iface=iface)
                time.sleep(2)
                sendp(p1, iface=iface)
                time.sleep(2)

        except KeyboardInterrupt:
            pass
