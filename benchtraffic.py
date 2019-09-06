import argparse
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


def send_pkt_thg(count, port_in):
    pkt = []
    print("create throughput buffer")
    for _ in range(0, int(count) + 500):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP())
        pkt.append(p)
    sendp(pkt, iface=port_in, verbose=False)


def send_pkt_lcy(count, port_in):
    print("create latency buffer")
    for _ in range(0, int(count)):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP()) / Raw(load=str(time.time()))
        sendp(p, iface=port_in,verbose=False)


def recv_pkt_thg(q, count, port_out):
    time_thg = []
    print("receiving packets")
    sniff(iface=port_out, prn=lambda x: time_thg.append(time.time()), count=int(count))
    pkts = len(time_thg)
    elapsed = time_thg[pkts - 1] - time_thg[0]
    thg = pkts / elapsed
    q.append(thg)


def recv_pkt_lcy(q, count, port_out):
    def handle_lcy(pkt):
        recv_time = time.time()
        send_time = float(pkt.getlayer(Raw).load)
        lcy = recv_time - send_time
        time_lcy.append(lcy)

    time_lcy = []
    print("receiving packets")
    sniff(iface=port_out, prn=handle_lcy, count=int(count))
    lcy = sum(time_lcy) / len(time_lcy)
    q.append(lcy)


def start_measure(q, count, port_int, port_out, rcv, snd):
    recv = threading.Thread(target=rcv, args=(q, count, port_out))
    send = threading.Thread(target=snd, args=(count, port_int))

    recv.start()
    time.sleep(1)
    send.start()

    while recv.is_alive():
        time.sleep(0.5)

    if send.is_alive():
        send.join()


def print_result(q):
   # a = np.array(q)
    str_list = ['{}'.format(x) for x in q]
    ret = " ".join(str_list)
    #total = (np.average(a))
    print(ret)
    #print("{} (response/s)".format(str(total)))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="traffic benchmarking")
    parser.add_argument('-l', '--loops', default=1, type=int, help="how many tests will be done")
    parser.add_argument('-c', '--count-macs', default=1, type=int, help="amount of uniques macs that will be generated")
    parser.add_argument('-i', '--port-in', type=str, required=True,
                        help="port where the packet will be sent")
    parser.add_argument('-o', '--port-out', type=str, required=True,
                        help="port where the packet will be received")
    parser.add_argument('-v', '--interval', default=2, type=int, help="interval between loops")
    parser.add_argument('-m', '--mode', default=1, type=int, required=True,
                        help="measure mode: 1 (throughput) or 0 (latency)")

    args = parser.parse_args()

    result = []
    for i in range(0, args.loops):
        if args.mode:
            print("Initializing throughput mode")
            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_out,
                          rcv=recv_pkt_thg, snd=send_pkt_thg)
        else:
            print("Initializing latency mode")
            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_out,
                          rcv=recv_pkt_lcy, snd=send_pkt_lcy)
        time.sleep(args.interval)

    print_result(result)
