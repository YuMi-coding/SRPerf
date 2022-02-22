#!/usr/bin/env python3
# Author: Yu Mi (yxm319@case.edu)
# Source splitter for IPv6 source address, which tries to replicate the stream template packet but
# use different source IPs to distribute the packet to different queues
import os
import dpkt
import argparse
import ipaddress

parser = argparse.ArgumentParser(description="IPv6 source splitter")
parser.add_argument("-i", "--input", help="The input pcap file.")
parser.add_argument("-r", "--replicates", help="The number of replicates.", default=4, type=int)
parser.add_argument("-o", "--output", help="The output pcap file name")

def get_output_filename(input_name, replicates):
    return input_name + "_replicated_" + str(replicates) + ".pcap"

def process(input_filename, replicates, output_filename):
    input_fd = open(input_filename, "rb")
    reader = dpkt.pcap.Reader(input_fd)
    output_fd = open(output_filename, "wb")
    writer = dpkt.pcap.Writer(output_fd)

    ts, pkt_buf = reader.__next__()
    ts_eps = 0.00001

    # Packet verification
    eth = dpkt.ethernet.Ethernet(pkt_buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP6:
        return
    ipv6 = eth.data

    for i in range(replicates):
        ipv6_src = ipaddress.ip_address(ipv6.src)
        temp = dpkt.ethernet.Ethernet(src=eth.src, dst = eth.dst, type=eth.type, data = ipv6)
        ts += ts_eps
        ipv6_src += 1
        ipv6.src = ipaddress.v6_int_to_packed(int(ipv6_src))
        writer.writepkt(temp, ts)



if __name__ == "__main__":
    args = parser.parse_args()
    if args.input is None or not os.path.isfile(args.input):
        print("Error in identifying input file.")
        exit(-1)

    if args.output is None:
        output_filename = get_output_filename(args.input, args.replicates)
    else:
        output_filename = args.output

    process(args.input, args.replicates, output_filename)