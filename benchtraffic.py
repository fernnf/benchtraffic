import argparse
import csv
import json

import numpy as np
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


def send_pkt_thg(count, port_in):
    pkt = []
    for _ in range(0, int(count) * 2):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP())
        pkt.append(p)

    sendp(pkt, iface=port_in, verbose=False)


def send_pkt_lcy(count, port_in):
    for _ in range(0, int(count)):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP()) / Raw(load=str(time.time()))
        sendp(p, iface=port_in, verbose=False)


def recv_pkt_thg(q, count, port_out):
    time_thg = []
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
        if not send.is_alive():
            recv.join(timeout=5)
            time.sleep(6)

    if send.is_alive():
        send.join(timeout=5)


def print_result(q, mode, name, out):
    type = ("throughput" if mode == 1 else "latency")
    a = np.array(q)
    total = (np.average(a))
    ret = {}
    ret.update({"name": name})
    ret.update({"type": type})
    ret.update({"rounds": {}})
    for i in range(0, len(q)):
        ret["rounds"].update({"{}".format(i + 1): q[i]})

    ret.update({"avarage": total})

    with open('{o}/{t}_{n}.json'.format(o=out, t=type, n=name), 'w') as outfile:
        json.dump([ret], outfile, indent=4, ensure_ascii=True)

    print(str([ret]))


def write_result(result, name, mode, out):
    type = ("throughput" if mode == 1 else "latency")
    a = np.array(result)
    total = (np.average(a))
    with open('{o}/{t}_{n}.csv'.format(o=out, t=type, n=name), mode='w') as csv_file:
        header = ["ROUND", "RESULT"]
        writer = csv.DictWriter(csv_file, fieldnames=header, delimiter=' ')
        writer.writeheader()
        for i in range(0, len(result)):
            writer.writerow({'ROUND': i + 1, 'RESULT': result[i]})

        writer.writerow({'ROUND': " ", 'RESULT': ""})
        writer.writerow({'ROUND': "AVG", 'RESULT': total})


def dir_path(path):
    if os.path.isfile(path):
        raise ValueError("this is not a path valid")

    if not os.path.isdir(path):
        os.makedirs(path)

    return path


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="traffic benchmarking")
    parser.add_argument('-l', '--loops', default=1, type=int, help="how many tests will be done")
    parser.add_argument('-c', '--count-macs', default=1, type=int, help="amount of uniques macs that will be generated")
    parser.add_argument('-i', '--port-in', default="dut1", type=str, help='port to send data')
    parser.add_argument('-o', '--port-out', default="dut2", type=str, help='port to receive data')
    parser.add_argument('-v', '--interval', default=2, type=int, help="interval between loops")
    parser.add_argument('-m', '--mode', default=1, type=int, required=True,
                        help="measure mode: 1 (throughput) or 0 (latency)")
    parser.add_argument('-n', '--name', default=datetime.now(), type=str, required=True, help="name file to write csv")
    parser.add_argument('-d', '--output', type=dir_path, required=True, help="directory to write files")

    args = parser.parse_args()

    result = []

    for i in range(0, args.loops):
        if args.mode:

            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_out,
                          rcv=recv_pkt_thg, snd=send_pkt_thg)
        else:

            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_in,
                          rcv=recv_pkt_lcy, snd=send_pkt_lcy)

        time.sleep(args.interval)

    write_result(result, args.name, args.mode, args.output)
    print_result(result, args.mode, args.name, args.output)
