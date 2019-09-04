from pyroute2 import IPRoute
from ryu.lib.ovs import vsctl
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


def create_pair(ifname, peer, mtu=9000):
    with IPRoute() as ipr:
        ipr.link("add", ifname=ifname, kind="veth", peer=peer)

        ifnet = ipr.link_lookup(ifname=ifname)[0]
        ifpeer = ipr.link_lookup(ifname=peer)[0]

        ipr.link("set", index=ifnet, mtu=mtu)
        ipr.link("set", index=ifnet, state="up")
        ipr.link("set", index=ifpeer, mtu=mtu)
        ipr.link("set", index=ifpeer, state="up")


def exist_interface(name):
    with IPRoute() as ipr:
        ifname = ipr.link_lookup(ifname=name)[0]
        return ifname


def ovs_command(addr, cmd, values):
    ovs = vsctl.VSCtl(addr)
    cmd = vsctl.VSCtlCommand(cmd, values)
    ovs.run_command(cmd)

    return cmd.result[0]


def add_port(addr, bridge, port, ofport):
    def add():
        ret = ovs_command(addr, "add-port", [bridge, port])
        if ret is not None:
            raise RuntimeError(ret)

    def config():
        ret = ovs_command(addr, "set", ["Interface", port, "ofport={}".format(ofport)])
        if ret is not None:
            raise RuntimeError(ret)
    try:
        add()
        config()
    except Exception as ex:
        raise RuntimeError(str(ex))


def rem_port(addr, bridge, port):
    def rem():
        ret = ovs_command(addr, "del-port", [bridge, port])
        if ret is not None:
            raise RuntimeError(ret)
    try:
        rem()
    except Exception as ex:
        raise RuntimeError(str(ex))


class TrafficGen(object):
    def __init__(self, num_macs, bridge, loops, gaps, port_int=None, port_out=None, throughput=True):
        self.num_macs = num_macs
        self.loops = loops,
        self.gaps = gaps
        self.send_time = []
        self.receive_time = []
        self.throughput = throughput
        self.port_in = port_int
        self.port_out = port_out

    def send_pkt_latency(self):
        pkts = []
        for _ in range(1, int(self.num_macs)):
            n = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP())
            pkts.append(time.time())
            sendp(n, iface)


time_list = []

for i in range(1, 10001):
    n = Ether(src=RandMAC(), dst=RandMAC()) / IP(dst=RandIP(), src=RandIP())
    time
    sendp(n, iface="link1-in", verbose=False)
