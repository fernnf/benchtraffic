import argparse
import csv
import json

import numpy as np
from pyroute2 import IPRoute
from ryu.lib.ovs import vsctl
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

MTU_DEFAULT = 9000
BRIDGE_DEFAULT = "tswitch0"
LOCAL = "tcp:127.0.0.1:6640"


def run_command(cmd, args, db_addr=LOCAL):
    ovsdb = vsctl.VSCtl(db_addr)
    command = vsctl.VSCtlCommand(cmd, args)
    ovsdb.run_command([command])
    return command.result


def set_ovsdb(db_addr=LOCAL, table=[], value=[]):
    command = "set"
    args = table + value
    return run_command(command, args, db_addr)


def get_ovsdb(db_addr=LOCAL, table=[], value=[]):
    command = "get"
    args = table + value
    return run_command(command, args, db_addr)


def add_port(db_addr, name, port_name, ofport=None):
    def adding():
        command = "add-port"
        args = [name, port_name]
        run_command(command, args, db_addr)

    def set_ofport():
        table = ["Interface"]
        value = [port_name, "ofport_request={ofport}".format(ofport=ofport)]
        set_ovsdb(db_addr, table, value)

    try:
        adding()
        if ofport is not None:
            set_ofport()
    except Exception as ex:
        raise RuntimeError(ex.args[0])


def add_vswitch():
    cmd = "add-br"
    args = ['vswitch0']
    ret = run_command(cmd=cmd, args=args, db_addr=LOCAL)[0]
    if ret is not None:
        raise RuntimeError(str(ret))


def config_link():
    for i in range(1, 3):
        ifname = "dut{}".format(i)
        peer = "peer{}".format(i)
        with IPRoute() as ipr:
            ipr.link("add", ifname=ifname, kind="veth", peer=peer)

            iface1 = ipr.link_lookup(ifname=ifname)[0]
            iface2 = ipr.link_lookup(ifname=peer)[0]

            ipr.link("set", index=iface1, mtu=MTU_DEFAULT)
            ipr.link("set", index=iface2, mtu=MTU_DEFAULT)

            ipr.link("set", index=iface1, state="up")
            ipr.link("set", index=iface2, state="up")

        add_port(LOCAL, BRIDGE_DEFAULT, peer, ofport=i)


def send_pkt_thg(count, port_in):
    pkt = []
    # print("create throughput buffer")
    for _ in range(0, int(count) + 500):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP())
        pkt.append(p)
    sendp(pkt, iface=port_in, verbose=False)


def send_pkt_lcy(count, port_in):
    # print("create latency buffer")
    for _ in range(0, int(count)):
        p = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP()) / Raw(load=str(time.time()))
        sendp(p, iface=port_in, verbose=False)


def recv_pkt_thg(q, count, port_out):
    time_thg = []
    # print("receiving packets")
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
    # print("receiving packets")
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

    if send.is_alive():
        send.join()


def print_result(q, mode, name, dir):
    m = ("throughput" if mode == 1 else "latency")
    time.sleep(1)
    a = np.array(q)
    total = (np.average(a))
    ret = {}
    ret.update({"name": name})
    ret.update({"type": m})
    ret.update({"rounds": {}})
    for i in range(0, len(q)):
        ret["rounds"].update({"{}".format(i + 1): q[i]})

    ret.update({"avarage": total})

    with open('{}/{}_{}.json'.format(dir, name, m), 'w') as outfile:
        json.dump([ret], outfile, indent=4, ensure_ascii=True)

    print([ret])


def write_result(result, name, mode, dir):
    mode = ("throughput" if mode == 1 else "latency")
    with open('{}/{}_{}.csv'.format(dir, name, mode), mode='w') as csv_file:
        header = ["ROUND", "RESULT"]
        writer = csv.DictWriter(csv_file, fieldnames=header, delimiter=' ')
        writer.writeheader()
        for i in range(0, len(result)):
            writer.writerow({'ROUND': i + 1, 'RESULT': result[i]})


def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        os.mkdir(path)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="traffic benchmarking")
    parser.add_argument('-l', '--loops', default=1, type=int, help="how many tests will be done")
    parser.add_argument('-c', '--count-macs', default=1, type=int, help="amount of uniques macs that will be generated")
    parser.add_argument('-i', '--port-in', default="dut1", type=str, help='port to send data')
    parser.add_argument('-o', '--port-out', default="dut2", type=str, help='port to receive data')
    parser.add_argument('-v', '--interval', default=2, type=int, help="interval between loops")
    parser.add_argument('-m', '--mode', default=1, type=int, required=True,
                        help="measure mode: 1 (throughput) or 0 (latency)")
    parser.add_argument('-n', '--name', default=datetime.now(), type=str, required=True,
                        help="name file to write csv")
    parser.add_argument('-t', '--output', type=dir_path,
                        help="output dir to write csv")

    args = parser.parse_args()

    result = []

    for i in range(0, args.loops):
        if args.mode:
            # print("Initializing throughput mode")
            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_out,
                          rcv=recv_pkt_thg, snd=send_pkt_thg)
        else:
            # print("Initializing latency mode")
            start_measure(q=result, count=args.count_macs, port_int=args.port_in, port_out=args.port_in,
                          rcv=recv_pkt_lcy, snd=send_pkt_lcy)

        time.sleep(args.interval)

    write_result(result, args.name, args.mode, args.output)
    print_result(result, args.mode, args.name, args.output)
