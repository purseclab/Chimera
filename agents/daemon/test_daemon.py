from util.daemon import Daemon
from test.topo import TestMininet
from flask import Flask, Response
from flask.globals import request
from daemon.consistencyTester import ConsistencyTester
from enum import Enum
import socket, sys
import six.moves.urllib.parse as urlparse
import subprocess, logging, json, httplib2, threading, os
import base64
from time import sleep
from test.stratum import StratumBmv2Switch

#LOG = logging.getLogger(__name__)
api = Flask(__name__)
logfile = '/tmp/ifuzzer/test-agent.log'
handler = logging.FileHandler(logfile)
api.logger.addHandler(handler)
api.logger.setLevel(logging.DEBUG)
net = None

sampleRate = 100
sniffWaitThreadList = {}
sniffWaitThreadByDst = {}
initMgmtIpList = []
discover_host = False
topoCommandList = []
consistencyTester = None

class SniffStatus(Enum):
    INIT = 1        # after __init__
    WAITING = 2     # during wait() with timeout
    PROCESSING = 3  # processing by sniff_result
    PROCESSED = 4   # processed by sniff_result
    STOPPED = 5     # done

class SniffWaitThread(threading.Thread):
    ''' TODO: set arg as dict() '''
    def __init__(self, key, seq, actionId, src, dstList,
            callback_url, mgmtSrc, waitMilliSec, sflow,
            failInTimeout=True):
        super().__init__()
        self.key = key
        self.seq = seq
        self.actionId = actionId
        self.src = src
        self.dstList = list(dstList)
        self.callback_url = callback_url
        self.isDone = False
        self.sflow = sflow
        self.mgmtSrc = mgmtSrc
        self.waitMilliSec = waitMilliSec
        self.waitCond = threading.Condition()
        self.lock = threading.Lock()
        self.status = SniffStatus.INIT

        if sflow or not failInTimeout:
            self.result = "success"
        else:
            self.result = "fail"

    def setWaitMilliSec(self, waitMilliSec):
        self.waitMilliSec = waitMilliSec

    def setFail(self):
        self.result = "fail"

    def stop(self, doCallback):
        global net, api
        self.isDone = True

        # clear temporary points
        numDst = len(self.dstList)
        if numDst > 0:
            if self.sflow:
                stopReplay(self.mgmtSrc, self.key, self.seq)

            net.delTestPoint(self.src, api.logger)

            for dst in self.dstList:
                if self.sflow:
                    # clear sflow commands
                    switch, errMsg = getExitSwitch(net, dst)
                    if errMsg is None:
                        switch.cmd(f"ovs-vsctl -- clear bridge {switch.name} sflow")

                mgmt, intf, errorMsg = getMgmtAddr(net, dst, True)

                # call stopsniff first
                if not self.sflow:
                    if mgmt is not None:
                        errorMsg, isStopped = stopSniff(mgmt, self.key, self.seq, (self.waitMilliSec // 1000) + 1, self.callback_url)
                        if isStopped:
                            numDst -= 1

                # then remove test point
                net.delTestPoint(dst, api.logger)

                if errorMsg is not None:
                    api.logger.error(f"fail to stop sniffing {dst}: {errorMsg}")

        if numDst > 0:
            if self.callback_url is not None and doCallback:
                ''' timeout '''
                httpTimeoutSec = (self.waitMilliSec // 1000) + 1
                h = httplib2.Http(timeout=httpTimeoutSec)
                resp, content = h.request(self.callback_url, method="POST",
                        headers={"Content-type": "application/json"},
                        body=json.dumps({"src": self.src,
                            "key": self.key,
                            "seq": self.seq,
                            "actionId": self.actionId,
                            "sflow": self.sflow,
                            "result": self.result}))

                if resp.status >= 300 or resp.status < 200:
                    api.logger.error(f"fail to send REST to {self.callback_url}: {resp.status}")

            if not self.sflow:
                api.logger.warn(f"timeout: sniff is not received from {self.dstList}")

        self.dstList.clear()

    def run(self):
        if len(self.dstList) == 0:
            return False

        # infinite loop. Clear by other requests
        if self.waitMilliSec == 0:
            return True

        doCallback = True
        with self.waitCond:
            while self.status == SniffStatus.PROCESSING:
                self.waitCond.wait()

            if self.status is not SniffStatus.STOPPED:
                self.status = SniffStatus.WAITING
                self.waitCond.notify()
                isNotified = self.waitCond.wait(timeout=(self.waitMilliSec / 1000))
                if isNotified:
                    doCallback = False
                    api.logger.warn(f"get notified")
                else:
                    api.logger.debug(f"sleep done")

            # Wait once more.
            while self.status == SniffStatus.PROCESSING:
                self.waitCond.wait()

            if self.status is not SniffStatus.STOPPED:
                # In this critical section, the test should be finished,
                # even though dp-agent waits to send sniff_result.
                self.stop(doCallback)
                self.status = SniffStatus.STOPPED
            self.waitCond.notify()


def getSniffThreadByDst(receiver):
    if receiver in sniffWaitThreadByDst:
        return sniffWaitThreadByDst[receiver]

    return []

def getIntfFromOvsPort(dp, portStr):
    portDescStrs = dp.cmdPrint(f"ovs-ofctl -OOpenFlow13 dump-ports-desc {dp.name}").splitlines()

    for portDescStr in portDescStrs:
        if portDescStr.lstrip().startswith(portStr + '('):
            intfStrs = portDescStr.split('(')
            return intfStrs[1].split(')')[0]

    return None

def getOvsPortFromIntf(dp, intfName):
    portDescStrs = dp.cmdPrint(f"ovs-ofctl -OOpenFlow13 dump-ports-desc {dp.name}").splitlines()

    intfNameStr = intfName + ")"
    for portDescStr in portDescStrs:
        if intfNameStr in portDescStr:
            portStr = portDescStr.split('(')
            return int(portStr[0])

    return 0

def getConnectedIntf(net, intf):
    # TODO: change to node
    for link in net.links:
        if link.intf1.name == intf:
            return link.intf2
        if link.intf2.name == intf:
            return link.intf1

    return None

'''
def delTmpPoint(net, addr):
    global tmpPointList
    if addr not in tmpPointList:
        return False

    switch, port = net.getSwitchAndPortFromAddr(addr)
    if switch is None:
        return False

    if not net.delPointOnTheFly(switch, int(port), logger=api.logger):
        return False

    tmpPointList.remove(addr)
    return True
'''


def stopSniff(mgmtDst, key, seq, toVal, callback_url):
    # STOP SNIFF to destinations
    url = urlparse.urlunsplit(('http', mgmtDst + ':5000', '/stopsniff', '', ''))
    api.logger.info(f"request stop-sniff to {url}")
    h = httplib2.Http(timeout=toVal)
    try:
        resp, content = h.request(url, method='POST',
                headers={"Content-type": "application/json"},
                body=json.dumps({"seq": seq, "key": key}))
    except socket.timeout:
        api.logger.info(f"timeout in stop-sniff request due to CALLBACK")
        return None, False

    if resp.status >= 300 or resp.status < 200:
        return f"connection fail: {resp.status}", False

    elif resp.status == 204:
        api.logger.info(f"timeout")
        return None, False

    elif resp.status == 200:
        retData = json.loads(content)
        api.logger.info(f"return test result: {retData} to {callback_url}")
        h = httplib2.Http(timeout=toVal)
        resp, content = h.request(callback_url, method='POST',
                headers={"Content-type": "application/json"},
                body=json.dumps(retData))

        return None, True

    return f"unknwon code: {resp.status}", False


def stopReplay(mgmtSrc, key, seq):
    # STOP REPLAY to source
    url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/stopreplay', '', ''))
    api.logger.info(f"request stop-replay to {url}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method='POST',
            headers={"Content-type": "application/json"},
            body=json.dumps({"seq": seq, "key": key}))

    if resp.status >= 300 or resp.status < 200:
        return f"connection fail: {resp.status}"

    return None

def sniffBddp(mgmt):
    # SNIFF BDDP to destinations
    url = urlparse.urlunsplit(('http', mgmt + ':5000', '/sniff_bddp', '', ''))
    api.logger.info(f"request stop-sniff to {url}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method='POST',
            headers={"Content-type": "application/json"},
            body=json.dumps({}))

    if resp.status >= 300 or resp.status < 200:
        return content, "connection fail: " + str(resp.status)

    return content, ""

def sendPacket(mgmt, req_body):
    url = urlparse.urlunsplit(('http', mgmt + ':5000', '/send', '', ''))
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method='POST',
            headers={"Content-type": "application/json"},
            body=json.dumps(req_body))
    if resp.status >= 300 or resp.status < 200:
        return content, "connection fail: " + str(resp.status)

    return content, ""


def stopReplay(mgmtSrc, key, seq):
    # STOP REPLAY to source
    url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/stopreplay', '', ''))
    api.logger.info(f"request stop-replay to {url}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method='POST',
            headers={"Content-type": "application/json"},
            body=json.dumps({"seq": seq, "key": key}))

def getExitSwitch(net, addr):

    ''' there must be ivs in tmpPointList '''
    try:
        socket.inet_aton(addr)
        for host in net.hosts:
            for intf in host.nameToIntf:
                if host.IP(intf) == addr:
                    return net.get(f's{host.name}')
        return None, None

    except socket.error:
        ''' switch/port '''
        switch, port = net.getSwitchAndPortFromAddr(addr, logger=api.logger)
        if switch is None:
            return None, f"cannot parse addr: {addr}"

        intf = getIntfFromOvsPort(switch, port)
        connIntf = getConnectedIntf(net, intf)

        if connIntf is None:
            return None, f"connected intf of {intf} is not found"
        return net.get(connIntf.node.name), None


def getMgmtAddr(net, addr, isReceiver, mtu=1500, isDebug=False):
    try:
        ''' IP address '''
        socket.inet_aton(addr)
        for host in net.hosts:
            for intf in host.nameToIntf:
                if host.IP(intf) == addr:
                    mgmt = host.IP('mgmt')
                    return mgmt, None, None
    except socket.error:
        ''' switch/port '''
        switch, port = net.getSwitchAndPortFromAddr(addr, logger=api.logger)
        if switch is None:
            return None, None, f"cannot parse addr: {addr}"
        if port is None or int(port) == 0:
            return None, None, f"wrong port: {addr}"

        if isinstance(switch, StratumBmv2Switch) and \
                switch.cpuPort == int(port):
            return None, "controller", None

        ''' Add temporal point '''
        mgmtNode, mgmtIntfName = net.addPointOnTheFly(switch, int(port),
                mtu=mtu, logger=api.logger)

        if mgmtNode is None:
            return None, None, f"cannot create tmp point to {switch.dpid}:{port}"
        if not isDebug:
            net.addTestPoint(addr, isReceiver)
            #tmpPointList.append(addr)

        return mgmtNode.IP('mgmt'), mgmtIntfName, None

    return None, None, "not found"

def send_topo(url):
    global net
    if url is None:
        return False

    resp_json = net.getTopoJson(topoCommandList)
    h = httplib2.Http(timeout=5)
    try:
        resp, content = h.request(url, method='POST',
                headers={"Content-type": "application/json"},
                body=json.dumps(resp_json))
    except Exception:
        ''' connection fails '''
        return False

    return True

def send_ping(_net, src, dst):

    api.logger.debug(f"send ping from {src} to {dst}")

    # convert src from data-ip to mgmt-ip
    mgmt, intf, errorMsg = getMgmtAddr(_net, src, False)

    if mgmt == None:
        return 404, json.dumps({"src": src, "dst": dst, "result": "fail", "errorMsg": errorMsg})

    # request to send ping to dp-agent
    url = urlparse.urlunsplit(('http', mgmt + ':5000', '/ping', '', ''))
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method='POST',
            headers={"Content-type": "application/json"},
            body=json.dumps({"src": src, "dst": dst}))

    return resp.status, content

def send_ping_all(_net):
    resp_json = {}
    host_json = []
    ping_threads = []
    for host in _net.data_hosts:
        addr = None
        for intf in host.nameToIntf:
            if intf != 'mgmt':
                addr = host.IP(intf)

                # append json first
                host_body = {}
                host_body["mac"] = host.MAC(intf)
                host_body["ip"] = host.IP(intf)
                host_json.append(host_body)

        # change dst address in subnet of intf (e.g. router address)
        if addr is not None:
            thread = threading.Thread(target=send_ping,
                    kwargs={'_net': _net, 'src': addr, 'dst': _net.routerAddr})
            ping_threads.append(thread)
            thread.start()

    for thread in ping_threads:
        thread.join()

    resp_json["hosts"] = host_json

    return resp_json

def init_network(_net, _url, _initMgmtIpList, _discover_host):

    if _net is None:
        return False

    for mgmtIp in _initMgmtIpList:
        _net.dpAgents[mgmtIp].setRunning(True)
    _initMgmtIpList = []

    # check whether all dp-agents are running
    finished = True
    for dpAgent in _net.dpAgents.values():
        if not dpAgent.isRunning():
            finished = False
            break

    if not finished:
        return False

    api.logger.info(f"all {len(_net.dpAgents.values())} dp-agents are running!")

    # if discover-host option is set, send init ping from all hosts
    if _discover_host:
        send_ping_all(_net)

    api.logger.info(f"######    test-agent is ready!   ######")

    send_topo(_url)

    return True

debug_sender = {}
debug_receiver = {}

@api.route('/debug/packet/init', methods=['POST'])
def debug_packet_init():
    global net
    req_body = request.get_json()

    if "output" not in req_body:
        return Response(response=json.dumps({"error": "no output"}), status=400, mimetype='application/json')

    deviceId = ""
    if "deviceId" in req_body:
        deviceId = req_body["deviceId"]

    receiverList = []
    for outputs in req_body["output"]:
        outPort = outputs["outPort"]
        receiverList.append(f"{deviceId}/{outPort}")

    for receiver in receiverList:
        mgmtDst, intfDst, errorMsg = getMgmtAddr(net, receiver, True)
        if mgmtDst is None:
            jbody = {}
            jbody["result"] = "fail"
            jbody["message"] = errorMsg
            api.logger.error(f"fail to get mgmt address of {receiver}: {errorMsg}")
            return Response(response=json.dumps(jbody), status=400, mimetype='application/json')
        debug_receiver["mgmt"] = mgmtDst
        debug_receiver["intf"] = intfDst
        debug_receiver["addr"] = receiver

    inPort = ""
    if "inPort" in req_body:
        inPort = req_body["inPort"]
    sender = f"{deviceId}/{inPort}"

    mgmtSrc, intfSrc, errorMsg = getMgmtAddr(net, sender, False)

    if mgmtSrc is None:
        jbody = {}
        jbody["result"] = "fail"
        jbody["message"] = errorMsg
        net.delTestPoint(sender, api.logger)
        api.logger.error(f"fail to get mgmt address of {sender}: {errorMsg}")
        return Response(response=json.dumps(jbody), status=400, mimetype='application/json')

    debug_sender["mgmt"] = mgmtSrc
    debug_sender["intf"] = intfSrc
    debug_sender["addr"] = sender

    return Response(response=json.dumps(debug_sender), status=200, mimetype='application/json')


@api.route('/debug/packet/sniff', methods=['POST'])
def debug_packet_sniff():
    req_body = request.get_json()

    if not debug_receiver:
        return Response(response=json.dumps({"error": "no receiver"}), status=408, mimetype='application/json')

    mgmtDst = debug_receiver["mgmt"]
    if debug_receiver["intf"] is not None:
        req_body["iface"] = debug_receiver["intf"]
    tmpOutPacket = None
    tmpOutPacketMask = None
    for outputs in req_body["output"]:
        tmpOutPacket = outputs["outPacket"]
        tmpOutPacketMask = outputs["outPacketMask"]
    req_body["outPacket"] = tmpOutPacket
    req_body["outPacketMask"] = tmpOutPacketMask
    req_body["ret_url"] = urlparse.urlunsplit(('http', f'{net.rootIP}:5000',
                '/sniff_result', request.query_string, ''))

    # REQUEST SNIFF to destinations
    url = urlparse.urlunsplit(('http', mgmtDst + ':5000', '/sniff', request.query_string, ''))
    api.logger.info(f"{url}: {req_body}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method=request.method,
            headers={"Content-type": "application/json"},
            body=json.dumps(req_body))

    return Response(response=content, status=resp.status, mimetype='application/json')

@api.route('/debug/packet/send', methods=['POST'])
def debug_packet_send():
    req_body = request.get_json()

    if not debug_sender:
        return Response(response=json.dumps({"error": "no sender"}), status=408, mimetype='application/json')

    mgmtSrc = debug_sender["mgmt"]
    if debug_sender["intf"] is not None:
        req_body["iface"] = debug_sender["intf"]

    # REQUEST SEND to sources
    url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/send', request.query_string, ''))
    api.logger.info(f"{url}: {req_body}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(url, method=request.method,
            headers={"Content-type": "application/json"},
            body=json.dumps(req_body))

    return Response(response=content, status=resp.status, mimetype='application/json')


@api.route('/debug/packet/clear', methods=['POST'])
def debug_packet_clear():
    global net

    if debug_sender:
        net.delTestPoint(debug_sender["addr"], api.logger)
        debug_sender.clear()

    if debug_receiver:
        net.delTestPoint(debug_receiver["addr"], api.logger)
        debug_receiver.clear()

    return Response(response=json.dumps(debug_sender), status=200, mimetype='application/json')


@api.route('/hello', methods=['GET'])
def receive_hello():
    global net, fuzzer_url, initMgmtIpList, discover_host

    # set given dp-agent as running
    mgmtIp = request.remote_addr
    if net is None:
        initMgmtIpList.append(mgmtIp)
        return Response(response=request.data, status=200)

    if mgmtIp in net.dpAgents:
        net.dpAgents[mgmtIp].setRunning(True)

    init_network(net, fuzzer_url, initMgmtIpList, discover_host)

    return Response(response=request.data, status=200)

def getPingDst(ipAddr):
    addrSplit = ipAddr.split('.')

    endAddr = '1'
    if addrSplit[3] == '1':
        endAddr = '2'

    return addrSplit[0] + '.' + addrSplit[1] + '.' + addrSplit[2] + '.' + endAddr


@api.route('/hello/onthefly', methods=['GET'])
def receive_hello_onthefly():
    global net

    mgmtIp = request.remote_addr

    thread = None
    # discover host
    for host in net.data_hosts:
        if mgmtIp != host.IP('mgmt'):
            continue

        for intf in host.nameToIntf:
            if intf != 'mgmt':
                addr = host.IP(intf)
                dstAddr = getPingDst(addr)
                api.logger.debug(f"discover host: src {addr}, mgmt {mgmtIp}, dst {dstAddr}")
                thread = threading.Thread(target=send_ping,
                        kwargs={'_net': net, 'src': addr, 'dst': dstAddr})
        break

    if thread is not None:
        thread.start()

    return Response(response=request.data, status=200)

'''
$ curl http://localhost:5000/dump
'''
@api.route('/dump', methods=['GET'])
def req_dump():
    global net
    resp_json = {}
    resp_json["testPointList"] = net.testPointList
    resp_json["recvPointList"] = net.receiverPointList
    return Response(response=json.dumps(resp_json), status=200, mimetype='application/json')

'''
$ curl http://localhost:5000/topology
'''
@api.route('/topology', methods=['GET'])
def req_topology():
    global net
    resp_json = net.getTopoJson(topoCommandList)
    return Response(response=json.dumps(resp_json), status=200, mimetype='application/json')

@api.route('/topology/all', methods=['GET'])
def req_topology_all():
    global net
    resp_json = net.getTopoJson(topoCommandList, True)
    return Response(response=json.dumps(resp_json), status=200, mimetype='application/json')

@api.route('/netcfg', methods=['GET'])
def req_netcfg():
    global net
    return Response(response=json.dumps(net.getNetcfg(logger=api.logger)),
            status=200, mimetype='application/json')

@api.route('/cov/dump', methods=['GET'])
def req_dump_cov_all():
    global net

    resp_json, status = net.dumpCovAll(logger=api.logger)

    return Response(response=json.dumps(resp_json), status=status, mimetype='application/json')

@api.route('/cov/dump/<deviceId>', methods=['GET'])
def req_dump_cov(deviceId):
    global net

    resp_json, status = net.dumpCov(deviceId, logger=api.logger)

    return Response(response=json.dumps(resp_json), status=status, mimetype='application/json')

@api.route('/cov/clear', methods=['GET'])
def req_clear_cov_all():
    global net

    resp_json, status = net.clearCovAll(logger=api.logger)

    return Response(response=json.dumps(resp_json), status=status, mimetype='application/json')

@api.route('/cov/clear/<deviceId>', methods=['GET'])
def req_clear_cov(deviceId):
    global net

    resp_json, status = net.clearCov(deviceId, logger=api.logger)

    return Response(response=json.dumps(resp_json), status=status, mimetype='application/json')

@api.route('/rule/<deviceId>', methods=['GET'])
def req_dump_rule(deviceId):
    global net

    resp_json, status = net.dumpRule(deviceId, logger=api.logger)

    return Response(response=json.dumps(resp_json), status=status, mimetype='application/json')

@api.route('/pingall', methods=['GET'])
def req_pingall():
    global net

    resp_json = send_ping_all(net)

    return Response(response=json.dumps(resp_json), status=200, mimetype='application/json')

'''
$ curl http://localhost:5000/sflow
'''
@api.route('/sflow/<int:idx>', methods=['GET'])
def req_sflow(idx=0):
    global net
    if net is None:
        return Response(response=request.data, status=428)

    ''' Deprecated '''
    switch, port = net.getTestPointByIdx(idx)
    if switch is None:
        return Response(response=request.data, status=404)

    return Response(response=json.dumps({"switch":"of:" + switch.dpid, "port":port}), status=200, mimetype='application/json')

'''
$ curl -X POST -H "Content-Type: application/json" -d '{"src": "10.0.0.1", "dst": "10.0.0.2"}' http://localhost:5000/ping
'''
@api.route('/ping', methods=['POST'])
def req_host():
    global net
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]

    try:
        status_code, content = send_ping(net, src, dst)
    except Exception:
        return Response(response=json.dumps(req_body), status=406, mimetype='application/json')

    return Response(response=content, status=status_code, mimetype='application/json')

@api.route('/sniff_result', methods=['POST'])
def receive_send_result():
    '''
    /sniff_result: clear metadata
    DP agent calls when it sniffs target packet
    '''
    global net, sniffWaitThreadList, sniffWaitThreadByDst
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    api.logger.info(f"get sniff_result {req_body}")

    if (key + seq) not in sniffWaitThreadList:
        return Response(response=request.data, status=404)

    sniffWaitThread = sniffWaitThreadList[key + seq]

    doClear = True
    isFinished = False
    with sniffWaitThread.waitCond:
        # sniff_result can be processed by other requests
        # TODO: Handle sniff_result then send response
        while sniffWaitThread.status == SniffStatus.PROCESSING:
            sniffWaitThread.waitCond.wait()

        if sniffWaitThread.status == SniffStatus.STOPPED:
            doClear = False
            isFinished = True

        else:
            sniffWaitThread.status = SniffStatus.PROCESSING

    api.logger.debug(f"[sniffWaitThread] size of dstList: {len(sniffWaitThread.dstList)}")

    result = "success"
    if "result" in req_body:
        result = req_body["result"]

    if result == "fail":
        for dst in sniffWaitThread.dstList:
            if doClear:
                net.delTestPoint(dst, api.logger)

            if dst in sniffWaitThreadByDst:
                sniffWaitThreadByDst[dst].clear()

        sniffWaitThread.dstList.clear()

    else:
        dst = None
        if "dst" in req_body:
            dst = req_body["dst"]

        if "receiver" in req_body:
            dst = req_body["receiver"]
            if doClear:
                ''' clear receiver point '''
                net.delTestPoint(dst, api.logger)

        if dst is not None:
            if dst in sniffWaitThreadByDst:
                sniffWaitThreadByDst[dst].clear()

            if dst in sniffWaitThread.dstList:
                sniffWaitThread.dstList.remove(dst)
    # TODO: check hosts not included in dstList
    if len(sniffWaitThread.dstList) == 0:
        isFinished = True
        jBody = {"key": key, "seq": seq, "result": result}
        if "src" in req_body:
            jBody["src"] = req_body["src"]

        if "actionId" in req_body:
            jBody["actionId"] = req_body["actionId"]

        ''' clear sender point '''
        if "sender" in req_body:
            if doClear:
                net.delTestPoint(req_body["sender"], api.logger)

        sniffWaitThreadList.pop(key+seq)

        if doClear and sniffWaitThread.callback_url is not None:
            api.logger.info(f"return test result: {req_body} to {sniffWaitThread.callback_url}")
            h = httplib2.Http(timeout=(sniffWaitThread.waitMilliSec / 1000))
            resp, content = h.request(sniffWaitThread.callback_url, method=request.method,
                    headers={"Content-type": "application/json"},
                    body=json.dumps(jBody))

    with sniffWaitThread.waitCond:
        if isFinished or sniffWaitThread.status == SniffStatus.STOPPED:
            sniffWaitThread.status = SniffStatus.STOPPED
        else:
            sniffWaitThread.status = SniffStatus.PROCESSED
        sniffWaitThread.waitCond.notify()

    return Response(response=request.data, status=200)


@api.route('/spoof_bddp', methods=['POST'])
def bddp_spoof():
    req_body = request.get_json()

    srcDeviceId = req_body["srcDeviceId"]
    srcPort = req_body["srcPort"]
    dstDeviceId = req_body["dstDeviceId"]
    dstPort = req_body["dstPort"]
    outPort = req_body["outPort"]

    src=f"{srcDeviceId}/{srcPort}"
    dst=f"{dstDeviceId}/{dstPort}"
    mgmtSrc, intfSrc, errorMsg = getMgmtAddr(net, src, False, isDebug=True)
    mgmtDst, intfDst, errorMsg = getMgmtAddr(net, dst, False, isDebug=True)

    content, errorMsg = sniffBddp(mgmtSrc)
    retData = json.loads(content)
    pktBytes = b'\x00' + outPort.to_bytes(1, 'big') + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbf\x01'
    if outPort == 255:
        pktBytes += b'\x7F\x80'
    pktBytes += base64.b64decode(retData["inPacket"])
    req_body["inPacket"] = base64.b64encode(pktBytes).decode("ascii")
    content, errorMsg = sendPacket(mgmtDst, req_body)

    return Response(response=content, status=200)

@api.route('/lfa', methods=['POST'])
def lfa_attack():
    req_body = request.get_json()

    srcDeviceId = req_body["srcDeviceId"]
    srcPort = req_body["srcPort"]
    dstDeviceId = req_body["dstDeviceId"]
    dstPort = req_body["dstPort"]

    src=f"{srcDeviceId}/{srcPort}"
    dst=f"{dstDeviceId}/{dstPort}"
    mgmtSrc, intfSrc, errorMsg = getMgmtAddr(net, src, False, isDebug=True)
    mgmtDst, intfDst, errorMsg = getMgmtAddr(net, dst, False, isDebug=True)

    content, errorMsg = sniffBddp(mgmtSrc)
    retData = json.loads(content)
    content, errorMsg = sendPacket(mgmtDst, retData)

    content, errorMsg = sniffBddp(mgmtDst)
    retData = json.loads(content)
    content, errorMsg = sendPacket(mgmtSrc, retData)

    return Response(response=content, status=200)

@api.route('/sniff_start', methods=['POST'])
def sniff_start():
    global sniffWaitThreadList
    req_body = request.get_json()

    seq = req_body["seq"]
    key = req_body["key"]
    actionId = req_body["actionId"]

    if (key + seq) not in sniffWaitThreadList:
        return Response(response=request.data, status=404)

    sniffWaitThread = sniffWaitThreadList[key + seq]
    if sniffWaitThread.actionId != actionId:
        return Response(response=request.data, status=409)
    sniffWaitThread.start()

    return Response(response=request.data, status=200)

@api.route('/sniff_stop', methods=['POST'])
def sniff_stop():
    global sniffWaitThreadList
    req_body = request.get_json()

    seq = req_body["seq"]
    key = req_body["key"]
    actionId = req_body["actionId"]

    if (key + seq) not in sniffWaitThreadList:
        return Response(response=request.data, status=404)

    sniffWaitThread = sniffWaitThreadList.pop(key + seq)
    if sniffWaitThread.actionId != actionId:
        return Response(response=request.data, status=409)

    if sniffWaitThread.is_alive():
        with sniffWaitThread.waitCond:
            sniffWaitThread.waitCond.notify()
            sniffWaitThread.join()
    else:
        sniffWaitThread.stop(False)

    return Response(response=request.data, status=200)

@api.route('/packet', methods=['POST'])
def packet_test():
    global net, sniffWaitThreadList

    req_body = request.get_json()
    headers={"Content-type": "application/json"}

    key = "packet"
    if "key" in req_body:
        key = req_body["key"]
    else:
        req_body["key"] = key

    actionId = None
    if "actionId" in req_body:
        actionId = req_body["actionId"]

    seq = "0"
    if "seq" in req_body:
        seq = req_body["seq"]

    deviceId = ""
    if "deviceId" in req_body:
        deviceId = req_body["deviceId"]

    inPort = ""
    if "inPort" in req_body:
        inPort = req_body["inPort"]

    waitMilliSec = 100
    if "wait_millisec" in req_body:
        waitMilliSec = req_body["wait_millisec"]
    elif "wait_sec" in req_body:
        waitMilliSec = req_body["wait_sec"] * 1000
    req_body["wait_millisec"] = waitMilliSec

    mtu = 1500
    inPacket = ""
    if "inPacket" in req_body:
        inPacketB64 = req_body["inPacket"]
        inPacket = base64.b64decode(inPacketB64)
        inPacketLen = len(inPacket)
        api.logger.debug(f"req packet: {inPacketLen}")
        if inPacketLen > mtu:
            mtu = inPacketLen

    senderList = [f"{deviceId}/{inPort}"]
    receiverList = []
    outPackets = []
    outPacketMasks = []
    failInTimeout = True
    numOutPorts = 0
    if "output" in req_body and len(req_body["output"]) > 0:
        for outputs in req_body["output"]:
            outPort = outputs["outPort"]
            if int(outPort) == 0:
                continue

            # check base64 encoding before testing
            outPacket = base64.b64decode(outputs["outPacket"])
            outPackets.append(outputs["outPacket"])

            base64.b64decode(outputs["outPacketMask"])
            outPacketMasks.append(outputs["outPacketMask"])
            outPacketLen = len(outPacket)
            api.logger.debug(f"exp packet: {outPacketLen}")
            if outPacketLen > mtu:
                mtu = outPacketLen

            # TODO: another deviceId of a path with multiple switches?
            receiverList.append(f"{deviceId}/{outPort}")

    # If receiverList is empty, check drop case
    if len(receiverList) == 0:
        failInTimeout = False
        for outPort in net.getAllDpPorts(deviceId):
            # Stratum uses port 0 as loopback
            if outPort == 0:
                continue

            if str(outPort) == inPort:
                api.logger.debug(f"skip {deviceId}:{inPort} for receiver")
                continue

            receiverList.append(f"{deviceId}/{outPort}")

    # callback from test-agent to fuzzer
    callback_url = None
    if "ret_url" in req_body:
        callback_url = req_body["ret_url"]

    # callback from dp-agent to test-agent
    req_body["ret_url"] = urlparse.urlunsplit(('http', f'{net.rootIP}:5000',
                '/sniff_result', request.query_string, ''))

    #req_body["senders"] = senderList
    #req_body["receivers"] = receiverList

    # check whether receivers are correct
    if len(receiverList) == 0:
        req_body["result"] = "fail"
        req_body["message"] = "No receiver"
        return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    for receiver in receiverList:
        mgmtDst, intfDst, errorMsg = getMgmtAddr(net, receiver, True, mtu=mtu)
        if errorMsg is not None:
            req_body["result"] = "fail"
            req_body["message"] = errorMsg
            api.logger.error(f"fail to get mgmt address of {receiver}: {errorMsg}")
            return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    seq_num = int(seq)      # incremented in loop
    mgmtSrcList = []
    for sender in senderList:
        seq = str(seq_num)
        req_body["seq"] = seq
        req_body["sender"] = sender

        mgmtSrc, intfSrc, errorMsg = getMgmtAddr(net, sender, False, mtu=mtu)

        if errorMsg is not None:
            req_body["result"] = "fail"
            req_body["message"] = errorMsg
            net.delTestPoint(sender, api.logger)
            api.logger.error(f"fail to get mgmt address of {sender}: {errorMsg}")
            return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

        sniffWaitThread = SniffWaitThread(key, seq, actionId, sender,
                receiverList, callback_url, mgmtSrc, waitMilliSec, False,
                failInTimeout=failInTimeout)

        try:
            tmpThread = sniffWaitThreadList[key + seq]
            if not tmpThread.isDone and tmpThread.is_alive():
                with tmpThread.waitCond:
                    tmpThread.waitCond.notify()
                    tmpThread.join()
                api.logger.warn(f"Thread for {key}:{seq} is not finished yet")
            sniffWaitThreadList.pop(key+seq)
        except KeyError as ke:
            ''' Not Found '''

        sniffWaitThreadList.update({key+seq:sniffWaitThread})

        failCnt = 0
        for idx, receiver in enumerate(receiverList):
            mgmtDst, intfDst, errMsg = getMgmtAddr(net, receiver, True, mtu=mtu)

            if errMsg is not None:
                failCnt += 1
                net.delTestPoint(receiver, api.logger)
                api.logger.debug(f"{errMsg}")
                continue

            req_body["receiver"] = receiver

            if receiver not in sniffWaitThreadByDst:
                sniffWaitThreadByDst[receiver] = []
            sniffWaitThreadByDst[receiver].append(sniffWaitThread)

            if intfDst == "controller":
                # Don't request SNIFF
                continue

            elif intfDst is not None:
                req_body["iface"] = intfDst
                api.logger.debug(f"sniff pkt from {mgmtDst}:{intfDst}")
            elif "iface" in req_body:
                del req_body["iface"]
                api.logger.debug(f"sniff pkt from {mgmtDst}")

            if len(outPackets) > 0:
                req_body["outPacket"] = outPackets[idx]
                req_body["outPacketMask"] = outPacketMasks[idx]
            else:
                # SNIFF no packet
                # XXX: How could it differentiate noisy packets?
                req_body["outPacket"] = ""

            if sender == receiver:
                req_body["loopback"] = "true"
                req_body["waitMilliSec"] = waitMilliSec + 500
                sniffWaitThread.setWaitMilliSec(waitMilliSec + 500)

            # REQUEST SNIFF to destinations
            url = urlparse.urlunsplit(('http', mgmtDst + ':5000', '/sniff', request.query_string, ''))
            api.logger.info(f"{url}: {req_body}")
            # No timeout for sniff request to wait stopping prev packetWorker
            h = httplib2.Http()
            resp, content = h.request(url, method=request.method, headers=headers,
                    body=json.dumps(req_body))
            if resp.status >= 300 or resp.status < 200:
                failCnt += 1
                net.delTestPoint(receiver, api.logger)
            else:
                api.logger.info(f"get 'sniff' response: {resp}, {content}")


        if len(receiverList) > 0:
            if failCnt == len(receiverList):
                net.delTestPoint(sender, api.logger)
                req_body["result"] = "fail"
                req_body["message"] = "all receivers are failed"
                return Response(response=req_body, status=400, mimetype='application/json')

            sleep(0.01)

        mgmtSrcListItem = {"ip": mgmtSrc}
        if intfSrc != "controller":
            if intfSrc is not None:
                req_body["iface"] = intfSrc
                mgmtSrcListItem["iface"] = intfSrc
                api.logger.debug(f"send pkt from {mgmtSrc}:{intfSrc}")
            elif "iface" in req_body:
                del req_body["iface"]
                api.logger.debug(f"send pkt from {mgmtSrc}")

            # REQUEST SEND to sources
            url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/send', request.query_string, ''))
            httpTimeoutSec = (waitMilliSec // 1000) + 1
            retStatus = 408
            for i in range(0, 4):
                try:
                    h = httplib2.Http(timeout=httpTimeoutSec)
                    resp, content = h.request(url, method=request.method, headers=headers,
                            body=json.dumps(req_body))
                    retStatus = resp.status
                    api.logger.info(f"[{retStatus}] {url}: {req_body}")
                    break

                except socket.timeout:
                    api.logger.warn(f"Cannot req to {url}")
                    httpTimeoutSec += 1


            ####
            # TODO: If request fails, return error with clear all data
            #       1) remove thread from sniffWaitThreadList - done
            #       2) turn off sniff process in destinations
            ####
            if retStatus >= 300 or retStatus < 200:
                sniffWaitThread = sniffWaitThreadList.pop(key+str(seq_num))
                sniffWaitThread.stop(False)
                return Response(response=content, status=retStatus, mimetype='application/json')
            else:
                # start sniffing after sending
                sniffWaitThread.start()
                api.logger.info(f"get 'send' response: {resp}, {content}")

            mgmtSrcList.append(mgmtSrcListItem)
            seq_num += 1

    api.logger.debug(f"req P4 packet test to {deviceId}:{inPort}")

    if "iface" in req_body:
        del req_body["iface"]

    req_body["mgmtSrcList"] = mgmtSrcList

    return Response(response=json.dumps(req_body), status=200, mimetype='application/json')


@api.route('/send', methods=['POST'])
def send_host():
    global net, sniffWaitThreadList, sniffWaitThreadByDst, sampleRate, ct
    # parse reqBody from request
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]
    headers={"Content-type": "application/json"}
    sflow = False

    callback_url = None
    if "ret_url" in req_body:
        callback_url = req_body["ret_url"]

    seq = "0"
    if "seq" in req_body:
        seq = req_body["seq"]

    key = ""
    if "key" in req_body:
        key = req_body["key"]

    if "sflow" in req_body:
        sflow = req_body["sflow"]

    waitMilliSec = 100
    if "wait_millisec" in req_body:
        waitMilliSec = req_body["wait_millisec"]
    elif "wait_sec" in req_body:
        waitMilliSec = req_body["wait_sec"] * 1000

    # get match from criteria
    criteria = []
    if "criteria" in req_body:
        criteria = req_body["criteria"]

    # fill reqBody which will send to dp-agent
    ret_url = urlparse.urlunsplit(('http', f'{net.rootIP}:5000', '/sniff_result', request.query_string, ''))
    jBody = {"src": src, "dst": dst, "seq": seq, "key": key,
        "ret_url": ret_url, "criteria": criteria, "sflow": sflow}
    jBody["wait_millisec"] = waitMilliSec

    actionId = None
    if "actionId" in req_body:
        actionId = req_body["actionId"]
        jBody["actionId"] = actionId

    # get all senders and receivers
    senderList = []
    if "senders" in req_body:
        senderList = req_body["senders"]
    else:
        senderList.append(src)

    receiverList = []
    if "receivers" in req_body:
        receiverList = req_body["receivers"]
    else:
        receiverList.append(dst)

    # check whether receivers are correct
    for receiver in receiverList:
        mgmtDst, intfDst, errorMsg = getMgmtAddr(net, receiver, True)
        if errorMsg is not None:
            jBody["result"] = "fail"
            jBody["message"] = errorMsg
            api.logger.error(f"fail to get mgmt address of {receiver}: {errorMsg}")
            return Response(response=json.dumps(jBody), status=400, mimetype='application/json')

    global consistencyTester
    if sflow:
        consistencyTester.init()

    # Main Processing
    seq_num = int(seq)      # incremented in loop
    mgmtSrcList = []
    for sender in senderList:
        """
        add waiting list
        TODO: support multiple sender in SniffWaitThread
        """
        seq = str(seq_num)
        jBody["seq"] = seq
        jBody["sender"] = sender

        # sender can be any host or port of link
        mgmtSrc, intfSrc, errorMsg = getMgmtAddr(net, sender, False)

        if errorMsg is not None:
            jBody["result"] = "fail"
            jBody["message"] = errorMsg
            net.delTestPoint(sender, api.logger)
            return Response(response=json.dumps(jBody), status=400, mimetype='application/json')

        # when sender is physical host, set ethDst as random
        if intfSrc is None:
            jBody["ethDst"] = "10:22:33:44:55:66"

        sniffWaitThread = SniffWaitThread(key, seq, actionId, sender,
                receiverList, callback_url, mgmtSrc, waitMilliSec, sflow)
        try:
            tmpThread = sniffWaitThreadList[key + seq]
            if not tmpThread.isDone and tmpThread.is_alive():
                with tmpThread.waitCond:
                    tmpThread.waitCond.notify()
                    tmpThread.join()
                api.logger.warn(f"Thread for {key}:{seq} is not finished yet")
            sniffWaitThreadList.pop(key+seq)
        except KeyError as ke:
            ''' Not Found '''

        sniffWaitThreadList.update({key+seq:sniffWaitThread})

        # receiver can be any host or port of link
        failCnt = 0
        for receiver in receiverList:
            mgmtDst, intfDst, errMsg = getMgmtAddr(net, receiver, True)
            if errMsg is not None:
                failCnt += 1
                net.delTestPoint(receiver, api.logger)
                api.logger.debug(f"{errMsg}")
                continue

            jBody["receiver"] = receiver

            if receiver not in sniffWaitThreadByDst:
                sniffWaitThreadByDst[receiver] = []
            sniffWaitThreadByDst[receiver].append(sniffWaitThread)

            if intfDst is not None:
                jBody["iface"] = intfDst
                api.logger.debug(f"sniff pkt from {mgmtDst}:{intfDst}")
            elif "iface" in jBody:
                del jBody["iface"]
                api.logger.debug(f"sniff pkt from {mgmtDst}")

            if sflow:
                # add sflow commands
                switch, errMsg = getExitSwitch(net, receiver)
                if errMsg is not None:
                    failCnt += 1
                    net.delTestPoint(receiver, api.logger)
                    api.logger.warn(f"{errMsg}")
                    continue

                # execute sflow command
                sflowCmdList = ["ovs-vsctl", "--", "--id=@sflow", "create"]
                sflowCmdList.append("sflow")
                if ct is None:
                    sflowCmdList.append(f"agent={switch.name}-eth3")
                    sflowCmdList.append(f"target=\\\"{net.rootIP}:6343\\\"")
                else:
                    sflowCmdList.append("agent=enp0s8")
                    sflowCmdList.append(f"target=\\\"{ct}:6343\\\"")
                sflowCmdList.append("header=128")
                sflowCmdList.append(f"sampling={sampleRate}")
                sflowCmdList.append("polling=1")
                sflowCmdList.append("--")
                sflowCmdList.append("set")
                sflowCmdList.append("bridge")
                sflowCmdList.append(f"{switch.name}")
                sflowCmdList.append("sflow=@sflow")
                sflowCmd = ' '.join(map(str,sflowCmdList))
                api.logger.debug(sflowCmd)
                switch.cmd(sflowCmd)

            else:
                # REQUEST SNIFF to destinations
                url = urlparse.urlunsplit(('http', mgmtDst + ':5000', '/sniff', request.query_string, ''))
                api.logger.info(f"request {jBody} to {url}")
                httpTimeoutSec = (waitMilliSec // 1000) + 1
                h = httplib2.Http(timeout=httpTimeoutSec)
                resp, content = h.request(url, method=request.method, headers=headers,
                        body=json.dumps(jBody))
                if resp.status >= 300 or resp.status < 200:
                    failCnt += 1
                    net.delTestPoint(receiver, api.logger)
                else:
                    api.logger.info(f"get 'sniff' response: {resp}, {content}")

        if failCnt == len(receiverList):
            net.delTestPoint(sender, api.logger)
            return Response(response=json.dumps([{"src": src, "dst": dst, "result": "fail"}]), status=400, mimetype='application/json')


        sleep(0.01)

        mgmtSrcListItem = {"ip": mgmtSrc}
        if intfSrc is not None:
            jBody["iface"] = intfSrc
            mgmtSrcListItem["iface"] = intfSrc
            api.logger.debug(f"send pkt from {mgmtSrc}:{intfSrc}")
        elif "iface" in jBody:
            del jBody["iface"]
            api.logger.debug(f"send pkt from {mgmtSrc}")

        if sflow:
            ''' sflow setting '''
            # REQUEST GEN_REPLAY to sources
            url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/genreplay', request.query_string, ''))
            api.logger.info(f"request {jBody} to {url}")
            h = httplib2.Http(timeout=5)
            resp, content = h.request(url, method=request.method, headers=headers,
                    body=json.dumps(jBody))

            # set cnt parameter of send request
            jBody["cnt"] = 5

        # REQUEST SEND to sources
        url = urlparse.urlunsplit(('http', mgmtSrc + ':5000', '/send', request.query_string, ''))
        api.logger.info(f"request {jBody} to {url}")
        httpTimeoutSec = (waitMilliSec // 1000) + 1
        h = httplib2.Http(timeout=httpTimeoutSec)
        resp, content = h.request(url, method=request.method, headers=headers,
                body=json.dumps(jBody))

        ####
        # TODO: If request fails, return error with clear all data
        #       1) remove thread from sniffWaitThreadList - done
        #       2) turn off sniff process in destinations
        ####
        if resp.status >= 300 or resp.status < 200:

            sniffWaitThread = sniffWaitThreadList.pop(key+str(seq_num))
            sniffWaitThread.stop(False)
            return Response(response=content, status=resp.status, mimetype='application/json')
        else:
            # start thread before sending
            sniffWaitThread.start()
            api.logger.info(f"get 'send' response: {resp}, {content}")

        mgmtSrcList.append(mgmtSrcListItem)
        seq_num += 1

    if "iface" in jBody:
        del jBody["iface"]

    jBody["mgmtSrcList"] = mgmtSrcList

    return Response(response=json.dumps(jBody), status=200, mimetype='application/json')

@api.route('/pazz_result', methods=['POST'])
def pazz_result():
    global net, sniffWaitThreadList, sniffWaitThreadByDst
    '''
    /pazz_result: stop tcpreplay, sflow, and clear points
    ConsistencyTester or Intender can request to stop packet-fuzzing.
    '''
    req_body = request.get_json()
    api.logger.info(f"get pazz_result {req_body}")

    result = "success"
    if "result" in req_body:
        result = req_body["result"]

    if "agent" in req_body:
        agent = req_body["agent"]
        receiver = req_body["receiver"]
        # TODO: add immediateStop option
        if result == "fail":
            # set fail as sniffWaitThread
            for sniffWaitThread in getSniffThreadByDst(receiver):
                sniffWaitThread.setFail()
    else:
        # Coming from fuzzer, clear sniffWaitThread
        key = req_body["key"]
        threadKeys = []
        for threadKey in sniffWaitThreadList.keys():
            if threadKey.startswith(key):
                threadKeys.append(threadKey)

        if len(threadKeys) == 0:
            return Response(response=request.data, status=404)

        # clear
        for threadKey in threadKeys:
            sniffWaitThread = sniffWaitThreadList.pop(threadKey)
            for dst in sniffWaitThread.dstList:
                if dst in sniffWaitThreadByDst:
                    sniffWaitThreadByDst[dst].clear()
            if sniffWaitThread.result == "fail":
                result = "fail"
            sniffWaitThread.stop(False)

    return Response(response=json.dumps({"result": result}), status=200, mimetype='application/json')


@api.route('/link/add', methods=['POST'])
def add_link():
    global net
    req_body = request.get_json()
    req_body["command"] = 'add-link'
    topoCommandList.append(req_body)

    src_body = req_body["src"]
    src_dpid = src_body["device"][3:]
    src_port = int(src_body["port"])

    dst_body = req_body["dst"]
    dst_dpid = dst_body["device"][3:]
    dst_port = int(dst_body["port"])

    api.logger.debug(f"add link: {req_body}")
    dataLink = net.addDataLink(src_dpid, src_port, dst_dpid, dst_port, logger=api.logger)

    if dataLink is not None:
        src_body["port"] = str(dataLink.port1)
        req_body["src"] = src_body
        dst_body["port"] = str(dataLink.port2)
        req_body["dst"] = dst_body
        status = 200
    else:
        status = 400

    return Response(response=json.dumps(req_body), status=status, mimetype='application/json')

@api.route('/device/add', methods=['POST'])
def add_device():
    global net
    req_body = request.get_json()
    req_body["command"] = 'add-device'
    topoCommandList.append(req_body)

    dpid = req_body["id"][3:]

    api.logger.debug(f"add device: {req_body}")
    ret = net.addDataSwitch(dpid.lower(), logger=api.logger)

    if ret:
        status = 200
    else:
        status = 400

    return Response(response=json.dumps(req_body), status=status, mimetype='application/json')

@api.route('/host/add', methods=['POST'])
def add_host():
    global net
    req_body = request.get_json()
    req_body["command"] = 'add-host'
    topoCommandList.append(req_body)

    dpid = req_body["dpid"][3:]
    ipList = req_body["ipAddresses"]

    mac = None
    if "mac" in req_body:
        mac = req_body["mac"]

    port = None
    if "port" in req_body:
        port = int(req_body["port"])

    api.logger.debug(f"add host: {req_body}")

    if len(ipList) == 0:
        return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    host = net.addDataHost(dpid.lower(), ipList[0], mac=mac, port=port, logger=api.logger)

    if host is None:
        return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    for intf in host.nameToIntf:
        if intf != 'mgmt':
            req_body["mac"] = host.MAC(intf)
            break

    intf = net.findIntfByHost(host, logger=api.logger)
    if intf is None:
        return Response(response=json.dumps(req_body), status=408, mimetype='application/json')

    req_body["dpid"] = getDeviceId(intf.node)
    newHostPort = getPortByIntf(intf, logger=api.logger)
    if newHostPort is not None:
        req_body["port"] = newHostPort

    return Response(response=json.dumps(req_body), status=200, mimetype='application/json')


@api.route('/link/delete', methods=['DELETE'])
def delete_link():
    global net
    req_body = request.get_json()
    req_body["command"] = 'delete-link'
    topoCommandList.append(req_body)

    src_body = req_body["src"]
    src_dpid = src_body["device"][3:]
    #src_port = src_body["port"]

    dst_body = req_body["dst"]
    dst_dpid = dst_body["device"][3:]
    #dst_port = dst_body["port"]

    api.logger.debug(f"remove link: {req_body}")
    ret, deleted_links = net.delDataLink(src_dpid, dst_dpid, logger=api.logger)

    if not ret:
        return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    if len(deleted_links) == 0:
        return Response(response=json.dumps(req_body), status=404, mimetype='application/json')

    # TODO: support multi-links
    src_body["port"] = str(deleted_links[0].port1)
    dst_body["port"] = str(deleted_links[0].port2)
    req_body["src"] = src_body
    req_body["dst"] = dst_body

    return Response(response=json.dumps(req_body), status=200, mimetype='application/json')

@api.route('/device/delete', methods=['DELETE'])
def delete_device():
    global net
    req_body = request.get_json()
    req_body["command"] = 'delete-device'
    topoCommandList.append(req_body)

    dpid = req_body["id"][3:]

    api.logger.debug(f"delete device: {req_body}")
    ret = net.delDataSwitch(dpid.lower(), logger=api.logger)

    if ret:
        status = 200
    else:
        status = 400

    return Response(response=json.dumps(req_body), status=status, mimetype='application/json')

@api.route('/host/delete', methods=['DELETE'])
def delete_host():
    global net
    req_body = request.get_json()
    req_body["command"] = 'delete-host'
    topoCommandList.append(req_body)

    dpid = req_body["dpid"][3:]
    ipList = req_body["ipAddresses"]

    api.logger.debug(f"delete host: {req_body}")

    if len(ipList) == 0:
        return Response(response=json.dumps(req_body), status=400, mimetype='application/json')

    ret, port = net.delDataHostByDpIp(dpid.lower(), ipList[0], logger=api.logger)

    if port is not None:
        req_body["port"] = str(port)

    if ret:
        status = 200
    else:
        status = 400

    return Response(response=json.dumps(req_body), status=status, mimetype='application/json')



''' Main Classes '''
class TestDaemon(Daemon):
    def __init__(self, options, pidfile, processname='', path='.', hostfile='/dev/null'):
        global sampleRate, ct
        super(TestDaemon, self).__init__(pidfile, processname,
                stdout=logfile, stderr=logfile)
        self.options = options
        self.path = path
        self.hostfile = hostfile
        self.tm = TestMininet(path)
        sampleRate = options.sampleRate
        ct = options.ct

    def run(self):
        global net, fuzzer_url, initMgmtIpList, discover_host, consistencyTester
        initMgmtIpList = []
        fuzzer_url = self.options.fuzzer_url
        discover_host = self.options.discover_host
        self.thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        self.thread.start()

        net = self.tm.startMininet(self.options, False)
        init_network(net, fuzzer_url, initMgmtIpList, discover_host)

        # execute local ct-agent, if there is no ct IP
        if self.options.pazzEnable and self.options.ct is None:
            consistencyTester = ConsistencyTester(net, self.options, self.path)
            consistencyTester.run()

    def before_stop(self):
        global net
        api.logger.info(f"Stopping test-agent...")

        if net is not None:
            api.logger.info(f"Removing {len(net.hosts)} hosts...")

            with open(self.hostfile, 'w+') as out:
                for host in net.hosts:
                    out.write(f"{host.name} ")

            self.tm.before_stop(False)

class TestFgDaemon():
    def __init__(self, options, path='.'):
        global sampleRate, ct
        self.options = options
        self.path = path
        self.tm = TestMininet(path)
        sampleRate = options.sampleRate
        ct = options.ct

    def start(self):
        global net, fuzzer_url, initMgmtIpList, consistencyTester
        initMgmtIpList = []
        fuzzer_url = self.options.fuzzer_url
        discover_host = self.options.discover_host
        thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        thread.start()

        # start network
        net = self.tm.startMininet(self.options, False)
        init_network(net, fuzzer_url, initMgmtIpList, discover_host)

        if self.options.pazzEnable and self.options.ct is None:
            consistencyTester = ConsistencyTester(net, self.options, self.path)
            consistencyTester.run()

    def stop(self):
        global net
        self.tm.before_stop(False)
        return True

    def status(self):
        ''' status '''

    def restart(self):
        ''' restart '''

