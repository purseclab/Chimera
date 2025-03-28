#!/usr/bin/python

'''
    TODO:
    - Fuzz
        - Topology
            - linear, loop, tree, fat-tree, leaf-spine
            - number of switch, link, host
            - bandwidth of each link
            - type of switch: OvS (OF 10~15), BMv2 (P4)
        - Network
            - L2/L3
            - Network Functions (LB, FW, IDS)
'''

from optparse import OptionParser
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, setLogLevel
from mininet.topolib import TreeTopo
from mininet.topo import Topo, LinearTopo
from mininet.link import TCLink, Intf
from mininet.node import Node, OVSSwitch, Controller, RemoteController, Host
from mininet.util import irange,dumpNodeConnections,waitListening
from flask.globals import request
import six.moves.urllib.parse as urlparse
import os, httplib2, subprocess, json, signal, re
from time import sleep
from test.stratum import StratumBmv2Switch, RemoteStratumSwitch

link1 = dict(bw=1000, delay='1ms', loss=0, max_queue_size=10000, use_htb=True)
link2 = dict(bw=15, delay='2ms', loss=0, max_queue_size=1000, use_htb=True)
link3 = dict(bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
link4 = dict(bw=5, delay='10ms', loss=0, max_queue_size=500, use_htb=True)
link5 = dict(bw=1, delay='15ms', loss=0, max_queue_size=100, use_htb=True)

linkHostLeaf = link1
hostList = []
ivHostList = []
ivSwitchList = []
ivEndSwitchList = []

def attachIntfToNode(node, intfName, port, mtu=1500, logger=None):
    if isinstance(node, StratumBmv2Switch):
        node.attach(intfName, port, mtu)

    else:
        if logger is not None:
            logger.info(f"exec: 'ovs-vsctl add-port {node.name} {intfName} -- set Interface {intfName} ofport={port}'" )

        # ADD PORT UNTIL THE PORT NUMBER IS CORRECT!
        recvPort = 0

        trial = 100
        while recvPort != port:
            if recvPort > 0:
                node.cmd(f"ovs-vsctl del-port {node.name} {intfName}")

            if trial <= 0:
                return False

            node.cmd( f"ovs-vsctl add-port {node.name} {intfName} -- set Interface {intfName} ofport={port}" )
            recvPort = getOvsPortFromIntf(node, intfName)
            trial -= 1

        node.cmd( 'ifconfig', intfName, 'mtu', mtu, 'up' )
        node.TCReapply( intfName )
    return True

def detachIntfFromNode(node, intfName):
    node.detach(intfName)
    node.cmd( 'ip link del', intfName )

def getDeviceId(switch):
    if isinstance(switch, StratumBmv2Switch):
        return switch.onosDeviceId
    return f"of:{switch.dpid}"

def getPortNoByIntf(intf, logger=None):
    switch = intf.node
    if isinstance(switch, StratumBmv2Switch):
        if intf not in switch.ports:
            if logger is not None:
                logger.error(f"{switch.name} does not have {intf.name}")
            return -1

        return switch.ports[intf]

    return getOvsPortFromIntf(intf.node, intf.name)

def getPortByIntf(intf, logger=None):
    switch = intf.node
    if isinstance(switch, StratumBmv2Switch):
        if intf not in switch.ports:
            if logger is not None:
                logger.error(f"{switch.name} does not have {intf.name}")
            return None

        return f"[{intf.name}]({switch.ports[intf]})"

    return str(getOvsPortFromIntf(intf.node, intf.name))

def findHostFromMac(net, mac):
    for host in net.data_hosts:
        for intf in host.nameToIntf:
            if intf != 'mgmt' and host.MAC(intf).lower() == mac.lower():
                return host

    return None

def findHostFromDpPort(net, switch, port, logger=None):
    for link in net.links:
        linkPort = None
        ives = None
        if link.intf1.node.name is switch.name:
            if logger is not None:
                logger.debug(f"{link.intf1.name}-{link.intf2.name}")
            linkPort = getOvsPortFromIntf(switch, link.inf1.name)
            ives = link.intf2.node

        if link.intf2.node.name is switch.name:
            if logger is not None:
                logger.debug(f"{link.intf2.name}-{link.intf1.name}")
            linkPort = getOvsPortFromIntf(switch, link.intf2.name)
            ives = link.intf1.node

        if port == linkPort:
            ''' found '''
            hostName = ives.name[1:]
            host = net[hostName]
            if logger is not None:
                logger.debug(f"host {host.name} is found")
            return host

    return None

def findHostFromDpIp(net, switch, ip, logger=None):
    foundHosts = set()
    for host in net.data_hosts:
        for intf in host.nameToIntf:
            if intf != 'mgmt' and host.IP(intf) == ip:
                ''' different hosts might have same ip '''
                foundHosts.add(host)
                break

    if len(foundHosts) == 0:
        return None

    for link in net.links:
        if link.intf1.node.name == switch.name:
            if link.intf2.node.name.startswith("sh") or \
                    link.intf2.node.name.startswith("sg"):
                connIntf = net.getConnectedIntfByName(f"{link.intf2.name[:-1]}2")
                if connIntf is not None:
                    suspectHostName = connIntf.node.name
            else:
                suspectHostName = link.intf2.node.name[1:]
        elif link.intf2.node.name == switch.name:
            if link.intf1.node.name.startswith("sh") or \
                    link.intf1.node.name.startswith("sg"):
                connIntf = net.getConnectedIntfByName(f"{link.intf1.name[:-1]}2")
                if connIntf is not None:
                    suspectHostName = connIntf.node.name
            else:
                suspectHostName = link.intf1.node.name[1:]
        else:
            continue

        for host in foundHosts:
            if host.name == suspectHostName:
                ''' found '''
                if logger is not None:
                    logger.debug(f"host {host.name} is found")
                return host

    return None

def findInvisibleSwitch(net, src, dst):
    global ivSwitchList

    for ivSwitch in ivSwitchList:
        if ivSwitch == (src.name + dst.name):
            return net[ivSwitch]
        elif ivSwitch == (dst.name + src.name):
            return net[ivSwitch]

    return None

def findDataLinkByDpid(net, dpid):
    links = []

    for data_link in net.data_links[:]:
        if ((data_link.node1.dpid == dpid) or
                (data_link.node2.dpid == dpid)):
            links.append(data_link)

    return links

def findDataLink(net, src, dst, srcPort, dstPort):
    for data_link in net.data_links[:]:
        if ((data_link.node1.dpid == src.dpid) and
            (data_link.node2.dpid == dst.dpid) and
            (data_link.port1 == srcPort) and
            (data_link.port2 == dstPort)):
                return data_link

        if ((data_link.node1.dpid == dst.dpid) and
            (data_link.node2.dpid == src.dpid) and
            (data_link.port1 == dstPort) and
            (data_link.port2 == srcPort)):
                return data_link

    return None

def delDataLinkBetween(net, src, dst, srcPort=None, dstPort=None, logger=None):
    deleted_links = []
    for data_link in net.data_links[:]:
        if ((data_link.node1.dpid == src.dpid) and
                (data_link.node2.dpid == dst.dpid)):

            if ((srcPort is not None) and (data_link.port1 != srcPort)):
                continue

            if ((dstPort is not None) and (data_link.port2 != dstPort)):
                continue

            logger.info(f"Remove {src.dpid}:{srcPort}-{dst.dpid}:{dstPort}")
            deleted_links.append(data_link)
            net.data_links.remove(data_link)

        if ((data_link.node1.dpid == dst.dpid) and
                (data_link.node2.dpid == src.dpid)):

            if ((dstPort is not None) and (data_link.port1 != dstPort)):
                continue

            if ((srcPort is not None) and (data_link.port2 != srcPort)):
                continue

            logger.info(f"Remove {dst.dpid}:{dstPort}-{src.dpid}:{srcPort}")
            deleted_links.append(data_link)
            net.data_links.remove(data_link)

    return deleted_links


def connectToRootNS( net, mgrSwitch, ip, routes ):
    root = Node( 'root', inNamespace=False )
    intf = net.addLink( root, mgrSwitch ).intf1
    root.setIP( ip, intf=intf )
    net.start()
    for route in routes:
        root.cmd( 'route add -net ' + route + ' dev ' + str(intf) )

def getIpFromSubnet( n, p, ipOnly=True ):
    arr1 = n.split('.')
    if len(arr1) != 4:
        return None

    arr2 = arr1[3].split('/')

    if len(arr2) != 2:
        return None

    if p >= 2**(32 - int(arr2[1])):
        return None

    ipInt = 0
    for i in range(0, 3):
        ipInt = ipInt * 256 + int(arr1[i])
    ipInt = ipInt * 256 + int(arr2[0])

    for i in range(0, 32 - int(arr2[1])):
        ipInt >>= 1

    for i in range(0, 32 - int(arr2[1])):
        ipInt <<= 1

    ipInt += p
    ipArr = []
    for i in range(0, 4):
        ipArr.append(str(ipInt % 256))
        ipInt //= 256

    if ipOnly:
        return ipArr[3] + '.' + ipArr[2] + '.' + ipArr[1] + '.' + ipArr[0]
    else:
        return ipArr[3] + '.' + ipArr[2] + '.' + ipArr[1] + '.' + ipArr[0] + '/' + arr2[1]


def addHostLinkWithInvisibleNode( topo, s, h, mgrSwitch ):
    ''' s --(1) endIv (2)-- h '''
    ''' endIv doesn't have mirroring port, but sflow port'''
    global ivEndSwitchList
    ivEndSwitch = topo.addSwitch('s%s' % (h), cls=MGRSwitch, failMode='secure', dpid=f'{h[1:]:0>15}B')
    topo.addLink(s, ivEndSwitch, port2=1)
    topo.addLink(h, ivEndSwitch, port2=2)
    ivEndSwitchList.append(ivEndSwitch)

    ''' sflow port'''
    topo.addLink(ivEndSwitch, mgrSwitch, port1=3)

def addHostLinkWithInvisibleNodeOnTheFly( net, s, h, mgrSwitch, sPort=None, mtu=1500, logger=None ):
    global ivEndSwitchList
    isNewIvs = False
    ivEndSwitch = None

    ''' try to find ivEndSwitch '''
    for switch in ivEndSwitchList:
        if switch == 's%s' % (h):
            ivEndSwitch =  net[switch]
            logger.info(f"{ivEndSwitch.name} is found for {s.name}-{h.name}")

    if ivEndSwitch is None:
        isNewIvs = True
        ivEndSwitch = net.addSwitch('s%s' % (h), cls=MGRSwitch, failMode='secure', dpid=f'{h.name[1:]:0>15}D')
        ivEndSwitch.start([])
        ivEndSwitchList.append(ivEndSwitch.name)

    ''' create link s-ivs / h-ivs '''
    if sPort is not None:
        link = net.addLink(s, ivEndSwitch, port1=sPort, port2=1, intfName2='s%s-eth1' % (h))
        attachIntfToNode(s, link.intf1.name, sPort, mtu)
        ivEndSwitch.attach(link.intf2.name)
    else:
        link = net.addLink(s, ivEndSwitch, port2=1, intfName2='s%s-eth1' % (h))
        s.attach(link.intf1.name)
        ivEndSwitch.attach(link.intf2.name)

    link2 = net.addLink(h, ivEndSwitch, port2=2, intfName2='s%s-eth2' % (h))
    ivEndSwitch.attach(link2.intf2.name)

    if isNewIvs:
        ''' sflow port'''
        sflowLink = net.addLink(ivEndSwitch, mgrSwitch, port1=3,
                intfName1='s%s-eth3' % (h))
        ivEndSwitch.attach(sflowLink.intf1.name)
        mgrSwitch.attach(sflowLink.intf2.name)

    ivEndSwitch.dpctl( 'add-flow', 'priority=10,in_port=1,action=output:2' )
    ivEndSwitch.dpctl( 'add-flow', 'priority=10,in_port=2,action=output:1' )

    return DataLink(s, h, link.intf1, link2.intf1, True)

def addLinkWithInvisibleNode( topo, src, dst, mgrSwitch, ivHost ):
    ''' src --(1) iv (2)-- dst '''
    ''' iv has both sflow port and mirroring ports'''
    global ivSwitchList

    dpid = '%s%s' % (src[1:], dst[1:])
    ivSwitch = topo.addSwitch('%s%s' % (src, dst), cls=MGRSwitch, failMode='secure', dpid=f'{dpid:0>15}A')

    topo.addLink(src, ivSwitch, port2=1)
    topo.addLink(dst, ivSwitch, port2=2)
    ivSwitchList.append(ivSwitch)

    ''' sflow port'''
    topo.addLink(ivSwitch, mgrSwitch, port1=3)

    if topo.staticMirrorEnable:
        ''' mirroring ports'''
        topo.addLink(ivSwitch, ivHost, port1=4, intfName2='%s%s-eth1' % (src, dst))
        topo.addLink(ivSwitch, ivHost, port1=5, intfName2='%s%s-eth2' % (src, dst))

def addLinkWithInvisibleNodeOnTheFly( net, src, dst, srcPort, dstPort, mgrSwitch, ivHost, mtu=1500, logger=None ):
    global ivSwitchList

    isNewIvs = False
    ivSwitch = findInvisibleSwitch(net, src, dst)
    if ivSwitch is None:
        isNewIvs = True
        dpid = '%s%s' % (src.name[1:], dst.name[1:])
        ivSwitch = net.addSwitch('%s%s' % (src, dst), cls=MGRSwitch, failMode='secure', dpid=f'{dpid:0>15}C')
        ivSwitch.start([])
        ivSwitchList.append(ivSwitch.name)

    else:
        logger.info(f"{ivSwitch.name} is found for {src.name}-{dst.name}")
        if ivSwitch.name == '%s%s' % (dst, src):
            tmp = src
            src = dst
            dst = tmp
            tmp = srcPort
            srcPort = dstPort
            dstPort = tmp

    ''' create link src-ivs / dst-ivs '''
    link = net.addLink(src, ivSwitch, port1=srcPort, port2=1, intfName2='%s%s-eth1' % (src, dst))
    attachIntfToNode(src, link.intf1.name, srcPort, mtu)
    ivSwitch.attach(link.intf2.name)

    link2 = net.addLink(dst, ivSwitch, port1=dstPort, port2=2, intfName2='%s%s-eth2' % (src, dst))
    attachIntfToNode(dst, link2.intf1.name, dstPort, mtu)
    ivSwitch.attach(link2.intf2.name)

    if isNewIvs:
        ''' sflow port'''
        net.addLink(ivSwitch, mgrSwitch, port1=3,
                intfName1='%s%s-eth3' % (src, dst))
        ivSwitch.attach('%s-eth3' % (ivSwitch))

        if net.staticMirrorEnable:
            ''' mirroring ports'''
            net.addLink(ivSwitch, ivHost, port1=4,
                    intfName1='%s%s-eth4' % (src, dst),
                    intfName2='%s%s-eth1' % (src, dst))
            net.addLink(ivSwitch, ivHost, port1=5,
                    intfName1='%s%s-eth5' % (src, dst),
                    intfName2='%s%s-eth2' % (src, dst))
            ivSwitch.attach('%s-eth4' % (ivSwitch))
            ivSwitch.attach('%s-eth5' % (ivSwitch))

    if net.staticMirrorEnable:
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=1,action=output:2,output:4' )
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=2,action=output:1,output:5' )
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=4,action=output:1' )
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=5,action=output:2' )
    else:
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=1,action=output:2' )
        ivSwitch.dpctl( 'add-flow', 'priority=10,in_port=2,action=output:1' )

    return DataLink(src, dst, link.intf1, link2.intf1, True)


def addSwitchOnTheFly( net, dpid ):
    switch = net.addSwitch(f"r{net.randSwitchIdx}", dpid=dpid, **net.switch_kwargs)
    switch.start(net.controllers)

    net.randSwitchIdx += 1;

    return switch

def addHostOnTheFly( net, dp, ip, mac, mgrSwitch, port=None, mtu=1500, logger=None ):
    # add DataLink
    if mac is not None:
        host = net.addHost(f"g{net.randHostIdx}", ip=ip, mac=mac, cls=TestHost)
    else:
        host = net.addHost(f"g{net.randHostIdx}", ip=ip, cls=TestHost)

    link = addHostLinkWithInvisibleNodeOnTheFly(net, dp, host, mgrSwitch, port, mtu, logger)

    '''
    if port is not None:
        logger.info(f"add host to {dp.name}:{port}")
        link = net.addLink(dp, net.get(f"g{net.randHostIdx}"), port1=port)
        attachIntfToNode(dp, link.intf1.name, port, logger)
    else:
        logger.info(f"add host to {dp.name}:p(x)")
        link = net.addLink(dp, net.get(f"g{net.randHostIdx}"))
        dp.attach(link.intf1.name)
    '''

    if mac is not None:
        host.setMAC(mac=mac, intf=link.intf2.name)
    host.setIP(ip=ip, intf=link.intf2.name)

    # add MgmtLink
    mgmtLink = net.addLink(host, mgrSwitch, intfName1='mgmt')
    mgrSwitch.attach(mgmtLink.intf2.name)
    mgmtIp = getIpFromSubnet(net.mgmt_net, net.postfix)
    host.setIP( ip=getIpFromSubnet(net.mgmt_net, net.postfix, False), intf='mgmt' )
    net.postfix += 1

    host.cmd(f"ifconfig {link.intf2.name} {ip}")
    host.cmd(f"ifconfig {mgmtLink.intf1.name} {mgmtIp}")
    host.cmd( '/usr/sbin/sshd -D &' )

    logfile = f"/tmp/ifuzzer/dp-agent-{host.name}.log"
    if net.agentPath != None:
        host.cmd(f"python3 {net.agentPath}/dp-agent.py -F -c {net.callbackRootUrl + '/onthefly'} -i {link.intf2.name} -n {host.name} start > {logfile} 2> {logfile} &")
        #host.cmd(f"python3 {net.agentPath}/dp-agent.py -F -c {net.callbackRootUrl + '/onthefly'} -i {link.intf2.name} -n {host.name} -p {net.agentPath}/util/packet.pcap start > {logfile} 2> {logfile} &")

    net.randHostIdx += 1

    if logger is not None:
        logger.info(f"{host.name} {host.MAC(link.intf2.name)} at {link.intf1.name} is added")

    return host


''' classes '''

class MGRSwitch( OVSSwitch ):
    def __init__( self, name, portNum=1, failMode='secure', datapath='kernel',
                  inband=False, protocols=None,
                  reconnectms=1000, stp=False, batch=False, **params ):
        super(MGRSwitch, self).__init__(name, failMode, datapath, inband, protocols,
                                        reconnectms, stp, batch, **params)
        self.portNum = portNum

    def start( self, controllers ):
        return OVSSwitch.start( self, [] )

'''
    TestTopo: Topology wrapper class
    with mgmt node (ivh) and switch (m1).
'''
class TestTopo(Topo):

    def __init__(self, options, **opts):
        super(TestTopo, self).__init__(**opts)

        self.staticMirrorEnable = options.staticMirrorEnable

        # add management node and switch
        self.mgrSwitch = self.addSwitch('m1', cls=MGRSwitch, failMode='standalone', dpid='000000000000000F')
        self.ivHost = self.addHost('ivh', ip=None, cls=TestHost)
        ivHostList.append(self.ivHost)
        self.addLink(self.ivHost, self.mgrSwitch, intfName1='mgmt')


class TestFatTreeTopo(TestTopo):

    CoreSwitchList = []
    AggSwitchList = []
    EdgeSwitchList = []
    HostList = []

    def __init__(self, options, **opts):
        super(TestFatTreeTopo, self).__init__(options, **opts)
        k = options.switches
        r = options.data_net

        self.pod = k
        self.iCoreLayerSwitch = (k//2)**2
        self.iAggLayerSwitch = k*k//2
        self.iEdgeLayerSwitch = k*k//2
        self.density = k//2
        self.iHost = self.iEdgeLayerSwitch * self.density

        # add switch
        for i in irange(1, self.iCoreLayerSwitch):
            self.CoreSwitchList.append(self.addSwitch(f"s1{i:02}",
                dpid=f"{0:013}1{i:02}", **options.switch_kwargs))

        for i in irange(1, self.iAggLayerSwitch):
            self.AggSwitchList.append(self.addSwitch(f"s2{i:02}",
                dpid=f"{0:013}2{i:02}", **options.switch_kwargs))

        for i in irange(1, self.iEdgeLayerSwitch):
            self.EdgeSwitchList.append(self.addSwitch(f"s3{i:02}",
                dpid=f"{0:013}3{i:02}", **options.switch_kwargs))

        # add host
        self.routerAddr = getIpFromSubnet(r, 1)
        postfix = 2
        for i in irange(1, self.iHost):
            ip = getIpFromSubnet(r, postfix, False)
            self.HostList.append(self.addHost(f"h{i:03}", ip=ip, cls=TestHost))
            postfix += 1

        # add link
        end = self.pod // 2
        ''' core - agg '''
        for i in range(0, self.iAggLayerSwitch, end):
            for j in range(0, end):
                for k in range(0, end):
                    addLinkWithInvisibleNode(self,
                            self.CoreSwitchList[j*end+k],
                            self.AggSwitchList[i+j],
                            self.mgrSwitch, self.ivHost)

        for i in range(0, self.iAggLayerSwitch, end):
            for j in range(0, end):
                for k in range(0, end):
                    addLinkWithInvisibleNode(self,
                            self.AggSwitchList[i+j],
                            self.EdgeSwitchList[i+k],
                            self.mgrSwitch, self.ivHost)

        for i in range(0, self.iEdgeLayerSwitch):
            for j in range(0, self.density):
                host = self.HostList[self.density * i + j]
                addHostLinkWithInvisibleNode(self,
                        self.EdgeSwitchList[i],
                        host, self.mgrSwitch)
                self.addLink(host, self.mgrSwitch, intfName1='mgmt')


class TestLinearTopo(TestTopo):

    def __init__(self, options, **opts):
        super(TestLinearTopo, self).__init__(options, **opts)

        ''' k = switch count, n = host count per switch '''
        k = options.switches
        n = options.hosts_per_switch
        r = options.data_net

        prevSwitch = self.mgrSwitch

        self.routerAddr = getIpFromSubnet(r, 1)
        postfix = 2
        for i in irange(0, k-1):
            switch = self.addSwitch('s%s' % (i+1), **options.switch_kwargs)
            if i > 0:
                addLinkWithInvisibleNode(self, prevSwitch, switch,
                        self.mgrSwitch, self.ivHost)

            prevSwitch = switch

            for j in irange(0, n-1):
                ip = getIpFromSubnet(r, postfix, False)
                host = self.addHost('h%s%s' % (j+1, i+1), ip=ip, cls=TestHost)
                postfix += 1
                addHostLinkWithInvisibleNode(self, switch,
                        host, self.mgrSwitch)
                self.addLink(host, self.mgrSwitch, intfName1='mgmt')
                hostList.append(host)


class TestTreeTopo(TestTopo):
    def __init__(self, options, **opts):
        super(TestTreeTopo, self).__init__(options, **opts)
        ''' k = tree depth, n = child cnt '''
        k = options.switches
        n = options.hosts_per_switch
        r = options.data_net

        self.routerAddr = getIpFromSubnet(r, 1)
        postfix = 2
        c = 1
        parentSwitches = list()

        # depth
        for i in irange(0, k):
            curSwitches = list()

            # for each child
            for j in irange(0, c-1):
                switch = self.addSwitch('s%s%s' % (i+1, j+1), **options.switch_kwargs)
                curSwitches.append(switch)
                if i > 0:
                    addLinkWithInvisibleNode(self, parentSwitches[(j // n)],
                            switch, self.mgrSwitch, self.ivHost)
            c = c * n
            parentSwitches = curSwitches

        # hosts (leaf-node)
        for j in irange(0, c-1):
            ip = getIpFromSubnet(r, postfix, False)
            hIdx = j % n
            sIdx = j // n
            host = self.addHost('h%ss%s%s' % (hIdx + 1, k, sIdx + 1), ip=ip, cls=TestHost)
            postfix += 1
            addHostLinkWithInvisibleNode(self,
                    parentSwitches[(sIdx)],
                    host, self.mgrSwitch)
            self.addLink(host, self.mgrSwitch, intfName1='mgmt')
            hostList.append(host)


class TestGridTopo(TestTopo):

    hostNum = 2
    SwitchList = []
    HostList = []

    def __init__(self, options, **opts):
        super(TestGridTopo, self).__init__(options, **opts)
        k = options.switches
        r = options.data_net

        self.lvl = k
        if k > 3 or k <= 1:
            sys.exit(f"TODO: level{k} should be 2 or 3.")

        # add switch: lvl(switchNum) = 2(4), 3(9), 4(16)
        self.switchNum = self.lvl ** 2
        for i in irange(1, self.switchNum):
            self.SwitchList.append(self.addSwitch('s%s' % (i),
                        dpid=f"{0:015}{i}",
                        **options.switch_kwargs))

        # add 2 hosts
        self.routerAddr = getIpFromSubnet(r, 1)
        postfix = 2
        for i in irange(1, self.hostNum):
            ip = getIpFromSubnet(r, postfix, False)
            self.HostList.append(self.addHost(f"h{i:03}", ip=ip, cls=TestHost))
            postfix += 1

        # add ingress host link
        addHostLinkWithInvisibleNode(self, self.SwitchList[0],
                self.HostList[0], self.mgrSwitch)
        self.addLink(self.HostList[0], self.mgrSwitch, intfName1='mgmt')

        # add switch link
        parentId = 0
        childId = 2
        for i in irange(1, self.lvl - 1):
            for j in range(0, 2 * i):
                if j % 2 == 0:
                    parentId += 1
                else:
                    childId += 1

                addLinkWithInvisibleNode(self,
                        self.SwitchList[parentId - 1],
                        self.SwitchList[childId - 1],
                        self.mgrSwitch, self.ivHost)
            childId += 1

        childId -= 1
        parentId += 1
        for i in range(self.lvl - 1, 0, -1):
            for j in range(0, 2 * i):
                if j % 2 == 0:
                    childId += 1
                else:
                    parentId += 1

                addLinkWithInvisibleNode(self,
                        self.SwitchList[parentId - 1],
                        self.SwitchList[childId - 1],
                        self.mgrSwitch, self.ivHost)
            parentId += 1

        # add egress host link
        addHostLinkWithInvisibleNode(self,
                self.SwitchList[self.switchNum - 1],
                self.HostList[1], self.mgrSwitch)
        self.addLink(self.HostList[1], self.mgrSwitch, intfName1='mgmt')

'''
 TestSingleTopo: create/get single switch connected with one IVS, hosts and IVH(s)

 e.g.) 5 ports, 2 hosts

             1(veth0)+--+1(veth1)            2+---1-[H_a]
             2(veth2)+--+3(veth3)            4+---2-[H_b]
                     |  |                     |
 [SWTICH:r0]-3(veth4)+--+5(veth5)-[IVS:ivs0]-6+--+3(r0-eth3)
             4(veth6)+--+7(veth7)            8+--+4(r0-eth4)-[IVH]
             5(veth8)+--+9(veth9)            10+-+5(r0-eth5)

'''
class TestSingleTopo(TestTopo):

    def __init__(self, options, **opts):
        super(TestSingleTopo, self).__init__(options, **opts)

        self.routerAddr = getIpFromSubnet(options.data_net, 1)

        chassisString = ""
        with open(options.chassisConfigFile, "r") as f:
            chassisString = f.read()
        portNum = chassisString.count('singleton_ports')
        self.targetSwitch = self.addSwitch('r0', cls=RemoteStratumSwitch,
                ipAddr=options.switchIpAddr,
                grpcPort=options.switchGrpcPort,
                portNum=portNum,
                pipeconf=options.device_proto,
                chassisConfigFile=options.chassisConfigFile)

        # Use switch option as a number of ports
        hostNum = options.hosts_per_switch
        if hostNum > portNum:
            hostNum = portNum

        global ivEndSwitchList
        self.ivEndSwitch = self.addSwitch('ivs0', cls=MGRSwitch,
                portNum=portNum, failMode='secure', dpid=f'{0:0>15}A')
        ivEndSwitchList.append(self.ivEndSwitch)

        # TODO: change manually-assigned ports (veth[X] & veth[X+1])
        for i in irange(1, portNum):
            if i <= hostNum:
                ip = getIpFromSubnet(options.data_net, i + 1, False)
                host = self.addHost(f'h{i}', ip=ip, cls=TestHost)
                # 1) add datalink first
                self.addLink(host, self.ivEndSwitch, port2=(i * 2))
                # 2) then, add mgmtlink
                self.addLink(host, self.mgrSwitch, intfName1='mgmt')
            else:
                self.addLink(self.ivHost, self.ivEndSwitch,
                             port2=(i * 2), intfName1=f'r0-eth{i}')



def getOvsPortFromIntf(dp, intfName):

    trial = 100
    while dp.waiting and trial > 0:
        sleep(0.05)
        trial -= 1

    ''' DO NOT TRUST CMDPRINT '''
    portDescStrs = dp.cmdPrint(f"ovs-ofctl -OOpenFlow13 dump-ports-desc {dp.name}").splitlines()

    intfNameStr = intfName + ")"
    for portDescStr in portDescStrs:
        if intfNameStr in portDescStr:
            portStr = portDescStr.split('(')
            return int(portStr[0])

    return 0

def getIntfFromOvsPort(dp, portStr):
    if dp.waiting:
        return None

    ''' DO NOT TRUST CMDPRINT '''
    portDescStrs = dp.cmdPrint(f"ovs-ofctl -OOpenFlow13 dump-ports-desc {dp.name}").splitlines()

    for portDescStr in portDescStrs:
        if portDescStr.lstrip().startswith(portStr + '('):
            intfStrs = portDescStr.split('(')
            return intfStrs[1].split(')')[0]

    return None

def getPortFromIntf(intfName):
    return int(re.findall(r'\d+', intfName)[-1])

''' classes '''

class DpAgent():
    def __init__(self, host):
        self.host = host
        self.running = False

    def isRunning(self):
        return self.running

    def setRunning(self, running):
        self.running = running


class DataLink():
    def __init__(self, node1, node2, intf1, intf2, port1=0, port2=0, onTheFly=False):
        self.node1 = node1
        self.node2 = node2
        self.intf1 = intf1
        self.intf2 = intf2
        if port1 > 0:
            self.port1 = port1
        elif onTheFly:
            self.port1 = getOvsPortFromIntf(node1, intf1.name)
        else:
            self.port1 = getPortFromIntf(intf1.name)

        if port2 > 0:
            self.port2 = port2
        elif onTheFly:
            self.port2 = getOvsPortFromIntf(node2, intf2.name)
        else:
            self.port2 = getPortFromIntf(intf2.name)

class TestHost(Host):
    def __init__(self, name, inNamespace=True, **params):
        Host.__init__(self, name, inNamespace=inNamespace, **params)
        self.sshdpopen = None

    def config(self, **params):
        r = super(Host, self).config(**params)
        self.sshdpopen = self.popen('/usr/sbin/sshd -D')
        print(f"run sshd as {self.sshdpopen.pid}")

        return r

    def terminate(self):
        if self.sshdpopen is not None:
            print(f"kill {self.sshdpopen.pid}")
            os.killpg(self.sshdpopen.pid, signal.SIGTERM)
            self.sshdpopen = None
        Host.terminate(self)

class DataMininet (Mininet):
    def __init__(self, options, **opts):
        super(DataMininet, self).__init__(**opts)
        self.randSwitchIdx = 1
        self.randHostIdx = 1
        self.postfix = 2
        self.subnetMask = int(options.data_net.split('/')[1])
        self.staticMirrorEnable = options.staticMirrorEnable
        self.pazzEnable = options.pazzEnable
        self.testPointList = []
        self.receiverPointList = []
        self.switch_kwargs = options.switch_kwargs
        self.deviceClass = options.switch_kwargs['cls']

    def build(self, **opts):
        super(DataMininet, self).build(**opts)
        '''
            - data_switches
            - data_links
            - data_hosts
        '''
        global ivSwitchList
        global ivEndSwitchList
        self.data_switches = []
        for switch in self.switches:
            if switch.name == 'm1':
                continue
            if switch.name in ivSwitchList:
                continue
            if switch.name in ivEndSwitchList:
                continue
            self.data_switches.append(switch)

        self.data_hosts = []
        for host in self.hosts:
            # set data_hosts
            if host.name not in ivHostList:
                self.data_hosts.append(host)


        self.data_links = []
        found_ivSwitchList = []
        for link in self.links:
            srcNode = link.intf1.node
            dstNode = link.intf2.node
            # skip all host link
            if dstNode.name == 'm1':
                continue

            if dstNode.name in found_ivSwitchList:
                continue

            if dstNode.name not in ivSwitchList:
                continue

            # search opposite link link.intf1 -- ivSwitch -- link2.intf1
            for link2 in self.links:
                if link is link2:
                    continue

                srcNode2 = link2.intf1.node
                dstNode2 = link2.intf2.node
                # found, if intf2 name is equal to ivSwitch
                if dstNode.name == dstNode2.name:
                    # make DataLink link.intf1 -> link2.intf1
                    dataLink = DataLink(srcNode, srcNode2, link.intf1, link2.intf1)
                    self.data_links.append(dataLink)
                    found_ivSwitchList.append(dstNode)
                    break

    def addTestPoint(self, addr, isReceiver):
        ''' testPoint has a lot of members '''
        if addr in self.testPointList:
            return False

        self.testPointList.append(addr)
        if isReceiver:
            self.receiverPointList.append(addr)

        return True

    def delTestPoint(self, addr, logger=None):
        if addr not in self.testPointList:
            if logger is not None:
                logger.error(f"delTestPoint(): {addr} not in testPointList")
            return False

        switch, port = self.getSwitchAndPortFromAddr(addr, logger)
        if switch is None:
            if logger is not None:
                logger.error(f"delTestPoint(): No switch for {addr}")
            return False

        # Skip if port is cpuPort
        if not isinstance(switch, StratumBmv2Switch) or \
                switch.cpuPort != int(port):

            if not self.delPointOnTheFly(switch, int(port), logger):
                return False

        self.testPointList.remove(addr)
        if addr in self.receiverPointList:
            self.receiverPointList.remove(addr)
        return True


    def getTestPointByIdx(self, idx, logger=None):
        if idx >= len(self.receiverPointList):
            return None, None

        addr = self.receiverPointList[idx]

        return self.getSwitchAndPortFromAddr(addr, logger)


    def addDataLink(self, srcDpid, srcPort, dstDpid, dstPort, logger=None):
        # (1) find src and dst
        src = self.getDpByDeviceId(srcDpid)
        if src is None:
            if logger is not None:
                logger.error(f"src {srcDpid} is not found")
            return None

        dst = self.getDpByDeviceId(dstDpid)
        if dst is None:
            if logger is not None:
                logger.error(f"dst {dstDpid} is not found")
            return None

        if findDataLink(self, src, dst, srcPort, dstPort) is not None:
            if logger is not None:
                logger.error(f"link exists")
            return None

        mtu = 1500
        if self.pazzEnable:
            mtu = 1580

        # (2) add src-dst link
        dataLink = addLinkWithInvisibleNodeOnTheFly(self, src, dst, srcPort, dstPort, self['m1'], self['ivh'], mtu, logger)
        if logger is not None:
            logger.debug(f"add dataLink {dataLink.node1.name}:{dataLink.port1} -> {dataLink.node2.name}:{dataLink.port2}")
        self.data_links.append(dataLink)

        return dataLink

    def addDataSwitch(self, dpid, logger=None):
        dp = self.getDpByDeviceId(dpid)
        if dp is not None:
            if logger is not None:
                logger.error(f"switch {dpid} exists.")
            return False

        dp = addSwitchOnTheFly(self, dpid)
        self.data_switches.append(dp)

        return True

    def addDataHost(self, dpid, ip, mac=None, port=None, logger=None):
        dp = self.getDpByDeviceId(dpid)
        if dp is None:
            if logger is not None:
                logger.error(f"switch {dpid} does not exist.")
            return None

        mtu = 1500
        if self.pazzEnable:
            mtu = 1580

        host = addHostOnTheFly(self, dp, ip, mac, self['m1'], port, mtu, logger)
        self.data_hosts.append(host)

        return host

    '''
    addPointOnTheFly: return connected node and intf.
    If there is no node on dp/port, create temp point.
    '''
    def addPointOnTheFly(self, dp, port, mtu=1500, logger=None):
        intf = self.getEventuallyIntfFromPort(dp, str(port))
        if self.pazzEnable:
            mtu += 80

        # non-existent port
        if intf is None:
            ''' create link dp-port to ivh '''
            link = self.addLink(dp, self['ivh'], port1=port,
                    intfName2='h%s-et%d' % (dp, port))

            if not attachIntfToNode(dp, link.intf1.name, port, mtu):
                return None, None

            self['ivh'].cmd( 'ifconfig', 'h%s-et%d' % (dp, port),
                    'mtu', mtu, 'up' )

            return self['ivh'], link.intf2.name

        # empty port
        connIntf = self.getConnectedIntf(intf)
        if connIntf is None:
            logger.warn(f"cannot find connected intf of {intf.name}")
            ''' try to add link '''
            link = self.addLink(dp, self['ivh'], port1=port,
                    intfName2='h%s-et%d' % (dp, port))


            ''' set mtu '''
            if isinstance(dp, StratumBmv2Switch):
                dp.enable_intf(intf.name)

            dp.cmd( 'ifconfig', intf.name, 'mtu', mtu, 'up' )
            self['ivh'].cmd( 'ifconfig', 'h%s-et%d' % (dp, port),
                    'mtu', mtu, 'up' )

            return self['ivh'], link.intf2.name

        # Exception: TestSingleTopo/IVS port
        if dp.name == "r0" and \
                    connIntf.node.name.startswith("ivs0"):
            ivsHostPort = port * 2
            ivsHostIntf = connIntf.node.intfs[ivsHostPort]
            hostIntf = self.getConnectedIntf(ivsHostIntf)
            if hostIntf is not None:
                return hostIntf.node, hostIntf.name

        # IVS port
        ''' find ivs '''
        if connIntf.name.startswith("sh") or \
                connIntf.name.startswith("sg"):
            ''' do nothing with S_HI '''
            return self[connIntf.node.name[1:]], None

        if connIntf.name.startswith("h") and connIntf.name.endswith("eth0"):
            ''' do nothing with Host '''
            return self[connIntf.node.name], None

        ''' switch (test-port) to ivh '''
        if self.staticMirrorEnable or connIntf.name.startswith("hs"):
            return self['ivh'], connIntf.name

        '''
        create link ivs to ivh
        e.g.) s204-ethX <-> s104s204-eth2 <-> s104s204-eth5 (ivh's s104s204-eth2)
        '''
        ivSwitch = connIntf.node
        ivsPort = int(connIntf.name[-1:])
        connPort = (ivsPort % 2) + 1
        mirrorPort = ivsPort + 3

        ''' skip if mirrorPort already exists '''
        if self.getIntfFromDpPort(ivSwitch, str(mirrorPort)) is not None:
            return self['ivh'], connIntf.name

        link = self.addLink(ivSwitch, self['ivh'], port1=mirrorPort,
                intfName2=f"{connIntf.name}")

        if not attachIntfToNode(ivSwitch, link.intf1.name, mirrorPort, mtu=mtu):
            return None, None

        if self.pazzEnable:
            ivSwitch.dpctl( "add-flow", f"priority=20,in_port={ivsPort},action=pop_verify,output:{connPort},output:{mirrorPort}")
            ivSwitch.dpctl( "add-flow", f"priority=20,in_port={mirrorPort},action=push_verify,output:{ivsPort}")
        else:
            ivSwitch.dpctl( "add-flow", f"priority=20,in_port={ivsPort},action=output:{connPort},output:{mirrorPort}")
            ivSwitch.dpctl( "add-flow", f"priority=20,in_port={mirrorPort},action=output:{ivsPort}")

        return self['ivh'], connIntf.name

    def detachIVSLinks(self, src, dst, ivSwitch):
        srcLinks = self.linksBetween(src, ivSwitch)
        for srcLink in srcLinks:
            if srcLink.intf1.name.startswith(src.name + '-'):
                detachIntfFromNode(src, srcLink.intf1.name)
                detachIntfFromNode(ivSwitch, srcLink.intf2.name)
            elif srcLink.intf2.name.startswith(src.name + '-'):
                detachIntfFromNode(src, srcLink.intf2.name)
                detachIntfFromNode(ivSwitch, srcLink.intf1.name)
        dstLinks = self.linksBetween(dst, ivSwitch)
        for dstLink in dstLinks:
            if dstLink.intf1.name.startswith(dst.name + '-'):
                detachIntfFromNode(dst, dstLink.intf1.name)
                detachIntfFromNode(ivSwitch, dstLink.intf2.name)
            elif dstLink.intf2.name.startswith(dst.name + '-'):
                detachIntfFromNode(dst, dstLink.intf2.name)
                detachIntfFromNode(ivSwitch, dstLink.intf1.name)


    def delDataLink(self, srcDpid, dstDpid, logger=None):
        global ivSwitchList

        # (1) find ivs between src and dst
        src = self.getDpByDeviceId(srcDpid)
        if src is None:
            if logger is not None:
                logger.error(f"src {srcDpid} is not found")
            return False, None

        dst = self.getDpByDeviceId(dstDpid)
        if dst is None:
            if logger is not None:
                logger.error(f"dst {dstDpid} is not found")
            return False, None

        ivSwitch = findInvisibleSwitch(self, src, dst)
        if ivSwitch is None:
            if logger is not None:
                logger.error(f"invisible switch is not found")
            return False, None

        # (2) remove src-ivs / dst-ivs from net
        if logger is not None:
            logger.debug(f"Remove {src.name}-{ivSwitch.name}")
            logger.debug(f"Remove {dst.name}-{ivSwitch.name}")

        self.detachIVSLinks(src, dst, ivSwitch)
        self.delLinkBetween(src, ivSwitch, allLinks=True)
        self.delLinkBetween(dst, ivSwitch, allLinks=True)
        ivSwitchList.remove(ivSwitch.name)
        self.delSwitch(ivSwitch)

        # (3) remove src-dst from net.data_links
        return True, delDataLinkBetween(self, src, dst, logger=logger)

    def delDataLinkByPort(self, srcDpid, srcPort, dstDpid, dstPort, logger=None):
        global ivSwitchList

        # (1) find ivs between src and dst
        src = self.getDpByDeviceId(srcDpid)
        if src is None:
            if logger is not None:
                logger.error(f"src {srcDpid} is not found")
            return False, None

        dst = self.getDpByDeviceId(dstDpid)
        if dst is None:
            if logger is not None:
                logger.error(f"dst {dstDpid} is not found")
            return False, None

        ivSwitch = findInvisibleSwitch(self, src, dst)
        if ivSwitch is None:
            if logger is not None:
                logger.error(f"invisible switch is not found")
            return False, None

        # (2) remove src-ivs / dst-ivs from net
        if logger is not None:
            logger.debug(f"Remove {src.name}-{ivSwitch.name}")
            logger.debug(f"Remove {dst.name}-{ivSwitch.name}")

        self.detachIVSLinks(src, dst, ivSwitch)
        self.delLinkBetween(src, ivSwitch)
        self.delLinkBetween(dst, ivSwitch)
        ivSwitchList.remove(ivSwitch.name)
        self.delSwitch(ivSwitch)

        # (3) remove src-dst from net.data_links
        return True, delDataLinkBetween(self, src, dst, srcPort, dstPort, logger)

    def delDataSwitch(self, dpid, logger=None):
        dp = self.getDpByDeviceId(dpid)
        if dp is None:
            if logger is not None:
                logger.error(f"switch {dpid} does not exist.")
            return False

        # check whether there are connected links
        links = findDataLinkByDpid(self, dpid)
        if len(links) > 0:
            if logger is not None:
                logger.error(f"links connected to {dpid} exist.")
                for link in links:
                    logger.error(f"  {link.intf1.name}-{link.intf2.name}")
            return False

        self.delSwitch(dp)
        self.data_switches.remove(dp)
        return True

    def delDataHostByDpPort(self, dpid, port, logger=None):
        switch = self.getDpByDeviceId(dpid)
        if switch is None:
            if logger is not None:
                logger.error(f"switch {dpid} is not found")
            return False

        host = findHostFromDpPort(self, switch, port, logger)
        if host is None:
            if logger is not None:
                logger.error(f"host {dpid}, {port} is not found")
            return False

        return self.delDataHost(switch, host, logger)

    def delDataHostByDpIp(self, dpid, ip, logger=None):
        switch = self.getDpByDeviceId(dpid)
        if switch is None:
            if logger is not None:
                logger.error(f"switch {dpid} is not found")
            return False

        host = findHostFromDpIp(self, switch, ip, logger)
        if host is None:
            if logger is not None:
                logger.error(f"host {dpid}, {ip} is not found")
            return False

        intf = self.findIntfByHost(host, logger=logger)

        return self.delDataHost(intf.node, host, logger), getPortByIntf(intf)

    def delDataHost(self, switch, host, logger=None):
        global ivEndSwitchList

        if switch is None:
            if logger is not None:
                logger.error(f"switch is None")
            return False

        if host is None:
            if logger is not None:
                logger.error(f"host is None")
            return False

        if logger is not None:
            logger.debug(f"remove host {host.name}")

        ivEndSwitch = None
        for ives in ivEndSwitchList:
            if ives == 's%s' % (host):
                ivEndSwitch = self[ives]
        if ivEndSwitch is None:
            if logger is not None:
                logger.error(f"ivEndSwitch is None")
            return False

        mgmt = self['m1']
        mgmtLinks = self.linksBetween(host, mgmt)
        for mgmtLink in mgmtLinks:
            if mgmtLink.intf1.name.startswith(host.name + '-'):
                detachIntfFromNode(mgmt, mgmtLink.intf2.name)
            elif mgmtLink.intf2.name.startswith(host.name + '-'):
                detachIntfFromNode(mgmt, mgmtLink.intf1.name)

        switchLinks = self.linksBetween(switch, ivEndSwitch)
        for switchLink in switchLinks:
            if switchLink.intf1.name.startswith(switch.name + '-'):
                detachIntfFromNode(switch, switchLink.intf1.name)
                detachIntfFromNode(ivEndSwitch, switchLink.intf2.name)
            elif switchLink.intf2.name.startswith(switch.name + '-'):
                detachIntfFromNode(switch, switchLink.intf2.name)
                detachIntfFromNode(ivEndSwitch, switchLink.intf1.name)
        hostLinks = self.linksBetween(host, ivEndSwitch)
        for hostLink in hostLinks:
            if hostLink.intf1.name.startswith(host.name + '-'):
                detachIntfFromNode(ivEndSwitch, hostLink.intf2.name)
            elif hostLink.intf2.name.startswith(host.name + '-'):
                detachIntfFromNode(ivEndSwitch, hostLink.intf1.name)

        self.delLinkBetween(host, mgmt)
        self.delLinkBetween(host, ivEndSwitch, allLinks=True)
        self.delLinkBetween(switch, ivEndSwitch, allLinks=True)
        ivEndSwitchList.remove(ivEndSwitch.name)
        self.delSwitch(ivEndSwitch)

        self.data_hosts.remove(host)
        self.delHost(host)

        return True

    '''
    delPointOnThFly: remove temp point
    '''
    def delPointOnTheFly(self, dp, port, logger=None):
        intf = self.getEventuallyIntfFromPort(dp, str(port))
        if intf is None:
            return True

        connIntf = self.getConnectedIntf(intf)

        # can be removed by previous deletion
        if connIntf is None:
            if isinstance(dp, StratumBmv2Switch):
                dp.detach(intf.name)
            return True

        # S_HI, Host port
        if connIntf.name.startswith("sh") or \
                connIntf.name.startswith("sg") or \
                connIntf.name.startswith("ivs0") or \
                (connIntf.name.startswith("h") and connIntf.name.endswith("eth0")):
            return True

        # empty port
        if connIntf.name.startswith("hs"):
            if isinstance(dp, StratumBmv2Switch):
                dp.detach(intf.name)
            self.delLinkBetween(dp, self['ivh'], allLinks=True)
            return True

        # IVS port
        if not self.staticMirrorEnable:
            if isinstance(dp, StratumBmv2Switch):
                dp.detach(intf.name)

            ivSwitch = connIntf.node
            ivsPort = int(connIntf.name[-1:])
            mirrorPort = ivsPort + 3
            self.delLinkBetween(ivSwitch, self['ivh'], allLinks=True)
            try:
                trial = 100
                while ivSwitch.waiting and trial > 0:
                    sleep(0.05)
                    trial -= 1

                ivSwitch.dpctl( "del-flows", "--strict", f"priority=20,in_port={ivsPort}" )

                trial = 100
                while ivSwitch.waiting and trial > 0:
                    sleep(0.05)
                    trial -= 1

                ivSwitch.dpctl( "del-flows", "--strict", f"priority=20,in_port={mirrorPort}" )
            except AssertionError:
                if logger is not None:
                    logger.error(f'fail to del-flows on {ivSwitch.name}')

        return True

    def findIntfByHost(self, host, logger=None):
        dataIntf = None
        for intf in host.nameToIntf:
            if intf != 'mgmt':
                dataIntf = intf
                break

        if dataIntf is None:
            if logger is not None:
                logger.warn(f"There is no dp for {host.name}")
            return None

        for link in self.links:
            if link.intf1.name == dataIntf:
                if link.intf2.node.name.startswith("sh") or \
                        link.intf2.node.name.startswith("sg"):
                    connIntf = self.getConnectedIntfByName(f"{link.intf2.name[:-1]}1")
                    if connIntf is not None:
                        return connIntf

                elif link.intf2.node.name.startswith("ivs0"):
                    # Exception: TestSingleTopo
                    ivsPort = getPortFromIntf(link.intf2.name)
                    switchPort = ivsPort / 2
                    if switchPort in self['r0'].intfs:
                        return self['r0'].intfs[switchPort]

                else:
                    return link.intf2

            elif link.intf2.name == dataIntf:
                if link.intf1.node.name.startswith("sh") or \
                        link.intf1.node.name.startswith("sg"):
                    connIntf = self.getConnectedIntfByName(f"{link.intf1.name[:-1]}1")
                    if connIntf is not None:
                        return connIntf
                elif link.intf1.node.name.startswith("ivs0"):
                    # Exception: TestSingleTopo
                    ivsPort = getPortFromIntf(link.intf1.name)
                    switchPort = ivsPort / 2
                    if switchPort in self['r0'].intfs:
                        return self['r0'].intfs[switchPort]

                else:
                    return link.intf1

        if logger is not None:
            logger.warn(f"There is no link for {dataIntf}")

        return None

    def getSwitchAndPortFromAddr(self, addr, mtu=1500, logger=None):
        arr = addr.split('/')
        if len(arr) != 2:
            if logger is not None:
                logger.error("mgmtAddr format is wrong")
            return None, None

        dpid = ""
        dpidArr = arr[0].split(':')
        if len(dpidArr) < 2:
            ''' dpid only '''
            dpid = f"of:{dpidArr[0]}"
        else:
            dpid = arr[0]

        for switch in self.switches:
            if getDeviceId(switch) == dpid:
                return switch, arr[1]

        if logger is not None:
            logger.error(f"switch {dpid} is not found")
        return None, None

    def getConnectedIntfByName(self, intfName):
        for link in self.links:
            if link.intf1.name == intfName:
                return link.intf2
            if link.intf2.name == intfName:
                return link.intf1

        return None

    def getConnectedIntf(self, intf):
        if isinstance(intf.node, RemoteStratumSwitch):
            # Exception: TestSingleTopo
            portNo = intf.node.ports[intf]
            return self['ivs0'].intfs[portNo * 2 - 1]

        return self.getConnectedIntfByName(intf.name)

    def getIntfFromDpPort(self, dp, portStr):
        portNo = int(portStr)
        if portNo not in dp.intfs.keys():
            return None

        return dp.intfs[portNo]

    def getEventuallyIntfFromPort(self, dp, portStr):
        intfName = None
        trial = 1
        while True:
            if isinstance(dp, StratumBmv2Switch):
                intfName = dp.getIntfFromPortNo(int(portStr))
            else:
                intfName = getIntfFromOvsPort(dp, portStr)
            if intfName is not None:
                return dp.nameToIntf[intfName]

            intf = self.getIntfFromDpPort(dp, portStr)
            if intf is None:
                return None

            # XXX: naive approach
            if trial <= 0:
                return intf

            trial -= 1
            sleep(0.05)

    def getDpByDeviceId(self, deviceId):
        for switch in self.data_switches:
            if isinstance(switch, StratumBmv2Switch) and \
                    switch.onosDeviceId == deviceId:
                return switch

            elif isinstance(switch, OVSSwitch) and \
                    deviceId.startswith("of:") and \
                    switch.dpid == deviceId[3:]:
                return switch
        return None

    def getAllDpPorts(self, deviceId, logger=None):
        switch = self.getDpByDeviceId(deviceId)
        if switch is None:
            if logger is not None:
                logger.warn(f"cannot find switch for {deviceId}")
            return []

        return list(switch.ports.values())

    def getTopoJson(self, topoCommandList=None, printAll=False, logger=None):
        resp_json = {}
        resp_json["topology"] = {}

        topo_json = {}
        switch_json = []
        switchList = []
        if printAll:
            switchList = self.switches
        else:
            switchList = self.data_switches

        for switch in switchList:
            switch_body = {}
            switch_body["id"] = getDeviceId(switch)
            switch_body["intfs"] = list(switch.nameToIntf.keys())
            switch_body["ports"] = list(switch.ports.values())
            switch_json.append(switch_body)
        topo_json["devices"] = switch_json

        link_json = []
        for link in self.data_links:
            src_body = {}
            src_body["device"] = getDeviceId(link.node1)
            src_body["port"] = getPortByIntf(link.intf1)

            dst_body = {}
            dst_body["device"] = getDeviceId(link.node2)
            dst_body["port"] = getPortByIntf(link.intf2)

            link_body = {}
            link_body["src"] = src_body
            link_body["dst"] = dst_body
            link_json.append(link_body)

        topo_json["links"] = link_json

        host_json = []
        for host in self.data_hosts:
            host_body = {}

            for intf in host.nameToIntf:
                # XXX: what if host has two interfaces?
                if intf != 'mgmt':
                    host_body["mac"] = host.MAC(intf)
                    host_body["ip"] = host.IP(intf)
                    break

            intf = self.findIntfByHost(host, logger=logger)
            if intf is not None:
                host_body["device"] = getDeviceId(intf.node)
                host_body["port"] = getPortByIntf(intf, logger=logger)

            host_json.append(host_body)

        topo_json["hosts"] = host_json

        if self.configTopo is not None:
            resp_json["configTopo"] = self.configTopo

        if topoCommandList is not None and len(topoCommandList) > 0:
            topo_json["operations"] = topoCommandList

        resp_json["topology"] = topo_json

        return resp_json


    def getNetcfg(self, logger=None):
        netcfgJson = {}
        if self.deviceClass is not StratumBmv2Switch:
            if logger is not None:
                logger.warn("device class is not BMv2")
            return netcfgJson

        ''' devices '''
        switchListNetcfg = {}
        for switch in self.data_switches:
            switchListNetcfg[switch.onosDeviceId] = switch.getOnosNetcfgObject()
        netcfgJson["devices"] = switchListNetcfg

        ''' ports '''
        portListNetcfg = {}
        for host in self.data_hosts:
            hostIps = []
            for intf in host.nameToIntf:
                if intf != 'mgmt':
                    hostIps.append(f"{host.IP(intf)}/{self.subnetMask}")
                    break

            # find host interface
            hostIntf = self.findIntfByHost(host)
            if hostIntf is None:
                continue

            dp = hostIntf.node
            port = getPortNoByIntf(hostIntf)
            if not isinstance(dp, StratumBmv2Switch):
                if logger is not None:
                    logger.warn(f"device is not bmv2")
                continue

            # TODO: vlan?
            intfNetcfg = {
                "name": host.name,
                "ips": hostIps
            }
            intfName = f"{dp.onosDeviceId}/{port}"

            intfListNetcfg = []
            if intfName in portListNetcfg.keys():
                intfListNetcfg = portListNetcfg[intfName]["interfaces"]

            intfListNetcfg.append(intfNetcfg)
            portListNetcfg[intfName] = {
                "interfaces": intfListNetcfg
            }

        netcfgJson["ports"] = portListNetcfg

        return netcfgJson

    def dumpCovAll(self, logger=None):
        covJsonArr = []
        for switch in self.data_switches:
            if not isinstance(switch, StratumBmv2Switch):
                continue

            respJson, status = self.dumpCovSwitch(switch, logger)
            if status != 200:
                continue

            covJsonArr.append(respJson)

        retJson = {}
        retJson["cov"] = covJsonArr
        if len(covJsonArr) == 0:
            retJson["message"] = "no available device"
            return retJson, 404

        return retJson, 200


    def dumpCov(self, deviceId, logger=None):
        respJson = {}
        status = 200

        switch = self.getDpByDeviceId(deviceId)
        respJson["id"] = deviceId
        if switch is None:
            respJson["message"] = f"{deviceId} is not found"
            status = 404
        elif not isinstance(switch, StratumBmv2Switch):
            respJson["message"] = f"device {deviceId} is not BMv2"
            status = 404
        else:
            respJson, status = self.dumpCovSwitch(switch, logger)

        retJson = {}
        retJson["cov"] = [respJson]

        return retJson, status


    def dumpCovSwitch(self, switch, logger=None):
        deviceId = switch.onosDeviceId
        covJson = {}
        covJson["id"] = deviceId
        if switch.getPid() == 0:
            covJson["message"] = f"device {deviceId} doesn't have pid"
            return covJson, 404

        filePath = switch.getTraceBitsFile()
        if filePath is None or len(filePath) == 0:
            covJson["message"] = f"device {deviceId} is not allowed to measure coverage"
            return covJson, 404

        # Measure coverage by signaling
        if not os.path.exists(filePath):
            open(filePath, 'a').close()

        stamp = os.stat(filePath).st_mtime
        os.kill(switch.getPid(), signal.SIGUSR1)

        # wait until the cov file has updated
        # TODO: parallelize waiting
        wait_cnt = 0
        while wait_cnt < 20:
            if stamp != os.stat(filePath).st_mtime:
                wait_cnt = -1
                break

            wait_cnt += 1
            sleep(0.05)

        if wait_cnt >= 0:
            covJson["message"] = f"timeout: cannot measure coverage of device {deviceId}"
            return covJson, 408

        covJson["filepath"] = filePath

        return covJson, 200


    def clearCovAll(self, logger=None):
        covJsonArr = []
        for switch in self.data_switches:
            if not isinstance(switch, StratumBmv2Switch):
                continue

            respJson, status = self.clearCovSwitch(switch, logger)
            if status != 200:
                continue

            covJsonArr.append(respJson)

        retJson = {}
        retJson["cov"] = covJsonArr
        if len(covJsonArr) == 0:
            retJson["message"] = "no available device"
            return retJson, 404

        return retJson, 200


    def clearCov(self, deviceId, logger=None):
        respJson = {}
        status = 200

        switch = self.getDpByDeviceId(deviceId)
        respJson["id"] = deviceId
        if switch is None:
            respJson["message"] = f"{deviceId} is not found"
            status = 404
        elif not isinstance(switch, StratumBmv2Switch):
            respJson["message"] = f"device {deviceId} is not BMv2"
            status = 404
        else:
            respJson, status = self.clearCovSwitch(switch, logger)

        retJson = {}
        retJson["cov"] = [respJson]

        return retJson, status


    def clearCovSwitch(self, switch, logger=None):
        deviceId = switch.onosDeviceId
        covJson = {}
        covJson["id"] = deviceId
        if switch.getPid() == 0:
            covJson["message"] = f"device {deviceId} doesn't have pid"
            return covJson, 404
        elif logger is not None:
            logger.debug(f"clear switch pid:{switch.getPid()}")

        os.kill(switch.getPid(), signal.SIGUSR2)

        return covJson, 200

    def dumpRule(self, deviceId, logger=None):
        retJson = {}
        status = 200
        switch = self.getDpByDeviceId(deviceId)
        retJson["id"] = deviceId
        if switch is None:
            retJson["message"] = f"{deviceId} is not found"
            status = 404
        elif not isinstance(switch, StratumBmv2Switch):
            retJson["message"] = f"device {deviceId} is not BMv2"
            status = 404
        else:
            retJson["entities"] = switch.get_current_rules()

        return retJson, status


class TestMininet():
    def __init__(self, path=None):
        self.net = None
        self.agentPath = path

    def startMininet(self, options, isFG=True):
        if options.verbose:
            setLogLevel('debug')
        else:
            setLogLevel('info')

        controllers = None
        options.switch_kwargs = {}
        if options.device_cls.lower() == 'bmv2':
            options.switch_kwargs['cls'] = StratumBmv2Switch
            options.switch_kwargs['pipeconf'] = options.device_proto
            options.switch_kwargs['ipAddr'] = options.switchIpAddr
            options.switch_kwargs['loglevel'] = options.switchLogLevel
            print("bmv2")
        else:
            options.switch_kwargs['cls'] = OVSSwitch
            options.switch_kwargs['protocols'] = options.device_proto
            if options.controllers:
                controllers = []
                for idx, addr in enumerate(options.controllers):
                    controllers.append(RemoteController( "c%d" % idx, ip=addr))

        if options.topology == 'linear':
            topo = TestLinearTopo( options )
        elif options.topology == 'tree':
            topo = TestTreeTopo( options )
        elif options.topology == 'fattree':
            topo = TestFatTreeTopo( options )
        elif options.topology == 'grid':
            topo = TestGridTopo( options )
        elif options.topology == 'single':
             options.switches = 1
             topo = TestSingleTopo( options )
        else:
            return None, None

        # initialize network
        if controllers is None:
            self.net = DataMininet( options, topo=topo, build=False, link=TCLink, controller=None )
        else:
            self.net = DataMininet( options, topo=topo, build=False, link=TCLink )

        self.net.routerAddr = topo.routerAddr

        # set config info
        self.net.configTopo = {}
        self.net.configTopo["topo"] = options.topology
        self.net.configTopo["switch"] = options.switches
        if options.topology != 'fattree':
            self.net.configTopo["host"] = options.hosts_per_switch

        for c in controllers or []:
            self.net.addController(c)

        self.net.build()

        for c in controllers or []:
            c.start()

        self.net.agentPath = self.agentPath
        self.net.mgmt_net = options.mgmt_net
        self.net.dpAgents = {}

        # add mgmt IP address for all hosts (including ivh)
        for host in self.net.hosts:
            mgmtIp = getIpFromSubnet(options.mgmt_net, self.net.postfix)
            host.setIP( ip=getIpFromSubnet(options.mgmt_net, self.net.postfix, False), intf='mgmt' )
            self.net.postfix += 1
            self.net.dpAgents[mgmtIp] = DpAgent(host)

        rootIP = getIpFromSubnet(options.mgmt_net, self.net.postfix)
        connectToRootNS( self.net, self.net[ 'm1' ], getIpFromSubnet(options.mgmt_net, self.net.postfix, False), [ options.mgmt_net ] )
        callbackRootUrl = urlparse.urlunsplit(('http', rootIP + ':5000', '/hello', '', ''))
        self.net.postfix += 1
        self.net.callbackRootUrl = callbackRootUrl
        self.net.rootIP = rootIP

        if isinstance(topo, TestSingleTopo):
            singleIvs = self.net[topo.ivEndSwitch]
            targetSwitch = self.net[topo.targetSwitch]

            for i in irange(0, singleIvs.portNum - 1):
                targetSwitch.addIntf(Intf(f'veth{i * 2}', node=targetSwitch), i+1)
                singleIvs.attach(f'veth{i * 2 + 1}')
                singleIvs.addIntf(Intf(f'veth{i * 2 + 1}', node=singleIvs), i*2+1)
                if f"h{i+1}" in self.net.hosts:
                    host = self.net[f"h{i+1}"]
                    hostIntf = None
                    for intf in host.intfs:
                        if intf.name != 'mgmt':
                            hostIntf = intf
                            break

                    self.data_links.append(DataLink(targetSwitch,
                                host, link.intf1, hostIntf,
                                port1=(i+1), port2=(i+1)))

        # execute agents in host
        for host in self.net.hosts:

            # (visible hosts) set default data interface
            # (invisible hosts) interface is given by REST for every send request
            iface = None
            if host.name not in ivHostList:
                for intf in host.nameToIntf:
                    if intf != 'mgmt':
                        iface = intf
                        break

            # dp-agent.py
            logfile = f"/tmp/ifuzzer/dp-agent-{host.name}.log"
            if self.agentPath != None:
                if iface is None:
                    host.cmd(f"python3 {self.agentPath}/dp-agent.py -F -c {callbackRootUrl} -n {host.name} -p {self.agentPath}/util/packet.pcap --log {logfile} start 2> {logfile} &")
                else:
                    host.cmd(f"python3 {self.agentPath}/dp-agent.py -F -c {callbackRootUrl} -i {iface} -n {host.name} -p {self.agentPath}/util/packet.pcap --log {logfile} start 2> {logfile} &")

        # change MTU size
        for switch in self.net.switches:
            for intf in switch.nameToIntf:
                switch.cmd('ifconfig', f'{intf}', 'mtu', 1580, 'up')

        global ivSwitchList
        # insert mirroring rules in invisible switches
        for ivSwitch in ivSwitchList:
            switch = self.net[ivSwitch]
            if options.staticMirrorEnable:
                switch.dpctl( 'add-flow', 'priority=10,in_port=1,action=output:2,output:4' )
                switch.dpctl( 'add-flow', 'priority=10,in_port=2,action=output:1,output:5' )
                switch.dpctl( 'add-flow', 'priority=10,in_port=4,action=output:1' )
                switch.dpctl( 'add-flow', 'priority=10,in_port=5,action=output:2' )
            else:
                for i in range(0, switch.portNum):
                    switch.dpctl( 'add-flow', f'priority=10,in_port={i*2 + 1},action=output:{i*2 + 2}' )
                    switch.dpctl( 'add-flow', f'priority=10,in_port={i*2 + 2},action=output:{i*2 + 1}' )

        global ivEndSwitchList
        for ivEndSwitch in ivEndSwitchList:
            switch = self.net[ivEndSwitch]

            for i in range(0, switch.portNum):
                switch.dpctl( 'add-flow', f'priority=10,in_port={i*2 + 1},action=output:{i*2 + 2}' )
                switch.dpctl( 'add-flow', f'priority=10,in_port={i*2 + 2},action=output:{i*2 + 1}' )

                if options.pazzEnable:
                    switch.dpctl( 'add-flow', f'priority=20,ip,in_port={i*2 + 1},action=pop_verify,output:{i*2 + 2}' )
                    switch.dpctl( 'add-flow', f'priority=20,ip,in_port={i*2 + 2},action=push_verify,output:{i*2 + 1}' )

        if isFG:
            CLI( self.net )
            self.before_stop(isFG)

        return self.net

    def before_stop(self, isFG):
        self.net.stop()




