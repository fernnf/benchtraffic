import argparse
import csv
import json

import coloredlogs
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Dot1Q

logger = logging.getLogger(__name__)

"""
def make_packet(vlan=False, timestap=False):
    etype_ip = 0x0800
    etype_vlan = 0x8100

    if vlan:
        ethernet = Ether(src=RandMAC, dst=ETHER_BROADCAST, type=etype_ip)
    else:
        ethernet = Ether(src=RandMAC, dst=ETHER_BROADCAST, type=etype_vlan) / Dot1Q(vlan=20)

    if timestap:
        ip = IP(src=RandIP, dst=RandIP) / Raw(load="{}".format(time.time()).encode(encoding="utf8"))
    else:
        ip = IP(src=RandIP, dst=RandIP) / Raw()
    p = ethernet / ip

    return p
"""


class GenTrafficThroughput(object):
    def __init__(self, macs, duts, l3addr, l2addr, type="throughput"):
        self.logger = logging.getLogger(__name__)
        self.signal_rcv = Event()
        self.macs = macs
        self.ports = duts
        self.result = []
        self.type = type
        self.l3addr = l3addr
        self.l2addr = l2addr

    def _make_sniff_throughput(self, r, s, p, m):
        logger.info("starting sniff")

        temp = []

        def reg_time(pkt):
            rcv_time = time.time()
            temp.append(rcv_time)

        sn = sniff(iface=p, prn=reg_time, count=m)
        s.clear()
        pkts = len(temp)
        elapsed = temp[pkts - 1] - temp[0]
        throughput = (pkts / elapsed)
        logger.info("{} response/sec  {}".format(throughput, sn))
        r.append(throughput)

    def _make_sendp_throughput(self, s, p, m, a, c):
        logger.info("starting sendp")

        def make_pkt():
            pkt = []
            for _ in range(0, 1000):
                # f = Ether(src=RandMAC(c), dst=RandMAC(),type=0x8100) / Dot1Q(vlan=20) / IP(dst=RandIP(),
                # src=RandIP(a)) / UDP(dport=80)
                f = Ether(src=RandMAC(c), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP(a))
                pkt.append(f)
            return pkt.copy()

        while s.is_set():
            sendp(make_pkt(), iface=p, verbose=False)

    def _make_sender_throughput(self):
        self.sender = Thread(target=self._make_sendp_throughput,
                             args=(self.signal_rcv, self.ports[0], self.macs, self.l3addr, self.l2addr))
        self.sender.name = "sendp"

    def _make_receiver_througput(self):
        self.receiver = Thread(target=self._make_sniff_throughput,
                               args=(self.result, self.signal_rcv, self.ports[1], self.macs))
        self.receiver.name = "sniff"
        self.signal_rcv.set()

    def run(self):
        logger.info("starting traffic generator")
        self._make_receiver_througput()
        self._make_sender_throughput()
        self.receiver.start()
        time.sleep(2)
        self.sender.start()
        while self.signal_rcv.is_set():
            time.sleep(1)
        else:
            self.sender.join(timeout=2)
            self.receiver.join(timeout=2)

    def get_result(self):
        return self.result[0]

    def get_type(self):
        return self.type

    def rcv_is_live(self):
        return self.receiver.is_alive()


class GenTrafficLatency(object):

    def __init__(self, macs, duts, l3addr, l2addr, type='latency', vlan=True):
        self.macs = macs
        self.signal_rcv = Event()
        self.ports = duts
        self.result = []
        self.type = type
        self.vlan = vlan
        self.l3addr = l3addr
        self.l2addr = l2addr

    def _make_sniff_latency(self, r, s, p, m):
        logger.info("starting sniff")

        temp = []

        def reg_time(pkt):
            try:
                recv_time = time.time()
                send_time = str(pkt.getlayer(Raw).load, encoding='utf-8')
                trip_time = recv_time - float(send_time)
                logger.info(trip_time)
                temp.append(trip_time)
            except Exception as ex:
                logger.error(str(ex))

        sn = sniff(iface=p, prn=reg_time, count=m)
        s.clear()
        latency = (sum(temp) / len(temp))
        r.append(latency)
        logger.info("latency: {} secs {}".format(latency, sn))

    def _make_sendp_latency(self, s, p, m, a, c):
        logger.info("starting sendp")
        while s.is_set():
            e = Ether(src=RandMAC(c), dst=RandMAC()) / Dot1Q(vlan=20)
            i = IP(src=RandIP(a), dst=RandIP())
            d = Raw(load="{}".format(time.time()).encode(encoding="utf8"))
            pkt = e / i / d
            sendp(pkt, iface=p, verbose=False)

    def _make_sender_latency(self):
        self.sender = Thread(target=self._make_sendp_latency,
                             args=(self.signal_rcv, self.ports[0], self.macs, self.l3addr, self.l2addr))
        self.sender.name = "sendp"

    def _make_receiver_latency(self):
        self.receiver = Thread(target=self._make_sniff_latency,
                               args=(self.result, self.signal_rcv, self.ports[1], self.macs))
        self.receiver.name = "sniff"
        self.signal_rcv.set()

    def run(self):
        logger.info("starting traffic generator")
        self._make_receiver_latency()
        self._make_sender_latency()
        self.receiver.start()
        time.sleep(2)
        self.sender.start()
        while self.signal_rcv.is_set():
            time.sleep(1)
        else:
            self.sender.join(timeout=2)
            self.receiver.join(timeout=2)

    def get_result(self):
        return self.result[0]

    def get_type(self):
        return self.type

    def rcv_is_live(self):
        return self.receiver.is_alive()


def dir_path(path):
    if os.path.isfile(path):
        raise ValueError("this is not a path valid")

    if not os.path.isdir(path):
        os.makedirs(path)

    return path


def write_csv(r, n, t, o):
    total = (sum(r) / len(r))

    with open('{o}/{t}_{n}.csv'.format(o=o, t=t, n=n), mode='w') as csv_file:
        header = ["ROUND", "RESULT"]
        writer = csv.DictWriter(csv_file, fieldnames=header, delimiter=' ')
        writer.writeheader()
        for i in range(0, len(r)):
            writer.writerow({'ROUND': i + 1, 'RESULT': result[i]})

        writer.writerow({'ROUND': None, 'RESULT': None})
        writer.writerow({'ROUND': "AVG", 'RESULT': total})


def write_json(r, n, t, o):
    total = (sum(r) / len(r))
    ret = {}
    ret.update({"name": n})
    ret.update({"type": t})
    ret.update({"rounds": {}})
    for i in range(0, len(r)):
        ret["rounds"].update({"{}".format(i + 1): r[i]})

    ret.update({"avarage": total})

    with open('{o}/{t}_{n}.json'.format(o=o, t=t, n=n), 'w') as outfile:
        json.dump([ret], outfile, indent=4, ensure_ascii=True)

    print(str([ret]))


if __name__ == '__main__':
    coloredlogs.install(level="INFO", logger=logger)
    logger.info("starting")

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
    parser.add_argument('-a', '--l3-address', default="0.0.0.0/0", type=str, help='port to receive data')
    parser.add_argument('-p', '--l2-address', default="*", type=str, help='port to receive data')
    args = parser.parse_args()

    result = []

    if args.mode:
        for i in range(0, args.loops):
            thg = GenTrafficThroughput(macs=args.count_macs, duts=(args.port_in, args.port_out), l3addr=args.l3_address,
                                       l2addr=args.l2_address)
            logger.info("{} loop {}".format(thg.get_type(), i + 1))
            thg.run()
            while thg.rcv_is_live():
                pass
            else:
                result.append(thg.get_result())
            time.sleep(args.interval)
    elif args.mode == 0:
        for i in range(0, args.loops):
            lty = GenTrafficLatency(macs=args.count_macs, duts=(args.port_in, args.port_out), l3addr=args.l3_address,
                                    l2addr=args.l2_address)
            logger.info("{} loop {}".format(lty.get_type(), i + 1))
            lty.run()
            while lty.rcv_is_live():
                pass
            else:
                result.append(lty.get_result())
            time.sleep(args.interval)

    else:
        logger.error("mode not found")
        parser.print_help()

    write_csv(result, args.name, ("throughput" if args.mode == 1 else "latency"), args.output)
    write_json(result, args.name, ("throughput" if args.mode == 1 else "latency"), args.output)
