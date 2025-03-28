from util.daemon import Daemon
from flask import Flask, Response
from flask.globals import request
from enum import Enum
from scapy.all import *
from scapy.utils import get_temp_file, wrpcap
import subprocess, logging, json, threading, httplib2, os, signal, multiprocessing, sys
import base64, netifaces, socket, copy
from queue import Queue

api = Flask(__name__)
replayProcList = {}
iface = None
pcap = None
pps = 1000
ppsMulti = 1000
sniffThreadList = {}
socketMap = {}
sniffStatus = None
sniffWaitCond = threading.Condition()
packetQueue = None
packetWorker = None
finalResult = None
ttsFilePath = None

class SniffStatus(Enum):
    INIT = 1        # after __init__
    WAITING = 2     # during wait() with timeout
    CALLBACK = 3    # processing by sniff_result
    STOPPING = 4    # processed by sniff_result
    STOPPED = 5     # done

def exec_tcpreplay(src, dst, iface):
    global pps, ppsMulti
    argv = ['tcpreplay']
    argv.append(f"--intf1={iface}")
    argv.append(f"--pps={pps}")
    argv.append(f"--pps-multi={ppsMulti}")
    argv.append("--loop=0")
    argv.append("--preload-pcap")

    pkt = Ether(src='70:88:99:00:11:22', dst='10:22:33:44:55:66')/IP(src=src, dst=dst)/TCP(sport=50000, dport=1234)
    f = get_temp_file()
    argv.append(f)
    wrpcap(f, pkt)

    return subprocess.Popen(argv, stdout=subprocess.PIPE,
            preexec_fn=os.setsid)

def markSniffing():
    global sniffStatus, sniffWaitCond
    with sniffWaitCond:
        sniffStatus = SniffStatus.WAITING
        sniffWaitCond.notify()

def putPacketInQueue(pkt, packetQueue):
    packetQueue.put({'P':pkt})
    return False

def clearPrevSniffers():
    global sniffThreadList, packetQueue, packetWorker

    # stop any sniff-thread
    numSniffThreads = len(sniffThreadList)

    if numSniffThreads > 0:
        for k in list(sniffThreadList.keys()):
            try:
                tmpThread = sniffThreadList[k]
                api.logger.info(f"* Stop sniffThread with {k}")
                del sniffThreadList[k]
                tmpThread.stop()

            except Scapy_Exception as se:
                ''' Not running '''

        if packetWorker is not None and packetWorker.is_alive():
            # Stop packetWorker again
            packetQueue.put({'R':True})
            packetWorker.join()
        api.logger.info(f"Before sending packet, stop {len(sniffThreadList)} sniffThread(s)")


def callback_to_sniff_waiter(req_body, result="success"):
    if "ret_url" not in req_body:
        return

    req_body["result"] = result
    ret_url = req_body["ret_url"]

    api.logger.info(f"Callback to sniff waiter: {ret_url} - {result}")
    h = httplib2.Http(timeout=5)
    resp, content = h.request(ret_url, method="POST",
            headers={"Content-type": "application/json"},
            body=json.dumps(req_body))

def handle_sniff(pkt, ip_proto, req_body):
    print("[sniff receiver]", pkt.summary())
    src = req_body["src"]
    dst = req_body["dst"]

    if (ip_proto == 17) and (UDP in pkt):
        rcvSrc = pkt.getlayer(IP).src
        if rcvSrc != src:
            return
        rcvDst = pkt.getlayer(IP).dst
        if rcvDst != dst:
            return

        # TODO: compare payload

    elif (ip_proto == 6) and (TCP in pkt):
        rcvSrc = pkt.getlayer(IP).src
        if rcvSrc != src:
            return
        rcvDst = pkt.getlayer(IP).dst
        if rcvDst != dst:
            return

        # TODO: compare payload

    elif (ip_proto == 1) and (ICMP in pkt):
        ''' matched '''

    elif (ip_proto == 0x84) and (SCTP in pkt):
        ''' matched '''

    else:
        return

    callback_to_sniff_waiter(req_body)

def stop_filter_by_string(packetQueue, ip_proto, req_body):
    global sniffWaitCond, sniffStatus, finalResult
    src = req_body["src"]
    dst = req_body["dst"]
    while True:
        pktVar = packetQueue.get()

        if pktVar.get('R'):
            packetQueue.task_done()
#           TODO: error doesn't print this message when POST://stopsniff
            api.logger.info(f"stop packet worker gracefully...")
            break

        pkt = pktVar.get('P')

        # WAITING or STOPPING

        if (ip_proto == 17) and (UDP in pkt):
            rcvSrc = pkt.getlayer(IP).src
            if rcvSrc != src:
                packetQueue.task_done()
                continue
            rcvDst = pkt.getlayer(IP).dst
            if rcvDst != dst:
                packetQueue.task_done()
                continue

            # TODO: compare payload

        elif (ip_proto == 6) and (TCP in pkt):
            rcvSrc = pkt.getlayer(IP).src
            if rcvSrc != src:
                packetQueue.task_done()
                continue
            rcvDst = pkt.getlayer(IP).dst
            if rcvDst != dst:
                packetQueue.task_done()
                continue

            # TODO: compare payload

        elif (ip_proto == 1) and (ICMP in pkt):
            ''' matched '''

        elif (ip_proto == 0x84) and (SCTP in pkt):
            ''' matched '''

        else:
            packetQueue.task_done()
            continue

        api.logger.info(f"[sniff received] {pkt.summary()}")

        # TODO: Update status
        with sniffWaitCond:
            if sniffStatus == SniffStatus.WAITING:
                sniffStatus = SniffStatus.CALLBACK
                callback_to_sniff_waiter(req_body)
                sniffStatus = SniffStatus.STOPPED
                sniffWaitCond.notify()

            elif sniffStatus == SniffStatus.STOPPING:
                req_body["result"] = "success"
                finalResult = copy.deepcopy(req_body)

            packetQueue.task_done()

def stop_filter_by_packet(packetQueue, req_body, expMaskedBytes, maskBytes):
    global sniffWaitCond, sniffStatus, finalResult, ttsFilePath
    skipInPacket = True
    while True:
        pktVar = packetQueue.get()

        if pktVar.get('R'):
            packetQueue.task_done()
#           TODO: error doesn't print this message when POST://stopsniff
            api.logger.info(f"stop packet worker gracefully...")
            break

        pkt = pktVar.get('P')

        pktBytes = raw(pkt)
        pktBytesLen = len(pktBytes)
        expLen = len(expMaskedBytes)

        if pktBytesLen < expLen:
            api.logger.debug(f"len(rx_pkt) ({pktBytesLen}) is shorter than len(expected_pkt) ({expLen})")
            if "ttf_mode" in req_body:
                pktMaskedBytes = bytes(a & b for (a, b) in zip(pktBytes, maskBytes[:pktBytesLen]))
                if pktMaskedBytes == expMaskedBytes[:pktBytesLen]:
                    with open(ttsFilePath + "-ttf-shrink", "w+") as f:
                        f.write("1")
            packetQueue.task_done()
            continue

        elif pktBytesLen > expLen:
            api.logger.debug(f"len(rx_pkt) ({pktBytesLen}) is longer than len(expected_pkt) ({expLen})")
            if "ttf_mode" in req_body:
                pktMaskedBytes = bytes(a & b for (a, b) in zip(pktBytes[:expLen], maskBytes))
                if pktMaskedBytes == expMaskedBytes:
                    with open(ttsFilePath + "-ttf-expand", "w+") as f:
                        f.write("1")
            packetQueue.task_done()
            continue

        # In case of loopback, skip inPacket
        if "loopback" in req_body and req_body["loopback"] == "true":
            if skipInPacket and pktBytes == base64.b64decode(req_body["inPacket"]):
                api.logger.debug(f"received packet is same as input packet")
                skipInPacket = False
                continue

        # Masking sniff packet
        pktMaskedBytes = bytes(a & b for (a, b) in zip(pktBytes, maskBytes))
        if pktMaskedBytes != expMaskedBytes:
            api.logger.debug(f"Not matched: {pkt.summary()}")
            packetQueue.task_done()
            continue

        api.logger.debug(f"[sniff received] {pkt.summary()}")
        # TODO: Update status
        with sniffWaitCond:
            if sniffStatus == SniffStatus.WAITING:
                sniffStatus = SniffStatus.CALLBACK
                callback_to_sniff_waiter(req_body)
                sniffStatus = SniffStatus.STOPPED
                sniffWaitCond.notify()

            elif sniffStatus == SniffStatus.STOPPING:
                req_body["result"] = "success"
                finalResult = copy.deepcopy(req_body)

            packetQueue.task_done()


def stop_filter_no_packet(packetQueue, req_body):
    global sniffWaitCond, sniffStatus, finalResult
    while True:
        pktVar = packetQueue.get()

        if pktVar.get('R'):
            packetQueue.task_done()
            api.logger.info(f"stop packet worker gracefully...")
            break

        pkt = pktVar.get('P')
        with sniffWaitCond:
            if sniffStatus == SniffStatus.STOPPED:
                packetQueue.task_done()
                continue
        ##
        # TODO: There should be False Negatives!
        #       Instead of protocol filters (ARP, LLDP, NDP),
        #       receive safe packets from controller.
        ##
        if pkt[Ether].type == 0x88cc or \
                pkt[Ether].type == 0x8999 or \
                pkt[Ether].type == 0x8942 or \
                pkt[Ether].type == 0x806:
            api.logger.debug("no packet: skip ARP/LLDP/BDDP")
            packetQueue.task_done()
            continue

        if IPv6 in pkt:
            pkt_ip6 = pkt[IPv6]
            if ICMPv6ND_RS in pkt_ip6:
                api.logger.debug("no packet: skip IPv6 NDP")
                packetQueue.task_done()
                continue

        api.logger.info(f"[sniff received] {pkt.summary()}")
        # TODO: Update status
        with sniffWaitCond:
            if sniffStatus == SniffStatus.WAITING:
                sniffStatus = SniffStatus.CALLBACK
                callback_to_sniff_waiter(req_body, "fail")
                sniffStatus = SniffStatus.STOPPED
                sniffWaitCond.notify()

            elif sniffStatus == SniffStatus.STOPPING:
                req_body["result"] = "fail"
                finalResult = copy.deepcopy(req_body)

            packetQueue.task_done()


''' REST APIs '''

@api.route('/ping', methods=['POST'])
def ping_host():
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]

    ret = subprocess.call(['ping', '-c', '1', '-w' '1', dst])
    if ret == 0:
        status_code = 200
        result = "success"
    elif ret == 1:
        status_code = 408
        result = "fail"
    elif ret == 2:
        status_code = 404
        result = "fail"
    else:
        status_code = 400
        result = "fail"

    return Response(response=json.dumps([{"src": src, "dst": dst, "result": result}]), status=status_code, mimetype='application/json')

def send_packet_func(target_iface, pkt, cnt):
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    soc.bind((target_iface, 0))

    try:
        sendp(pkt, iface=target_iface, count=cnt, socket=soc)
    except Exception as E:
        sendp(pkt, iface=target_iface, count=cnt)
    finally:
        soc.close()


@api.route('/send', methods=['POST'])
def send_host():
    global iface, socketMap, sniffThreadList, packetQueue, packetWorker
    req_body = request.get_json()

    # read target_iface
    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    waitMilliSec = 100
    if "wait_millisec" in req_body:
        waitMilliSec = req_body["wait_millisec"]

    # Fail if no target_iface
    if target_iface not in netifaces.interfaces():
        req_body["result"] = "fail"
        api.logger.error(f"{target_iface} is not in host")

        return Response(response=req_body, status=404, mimetype='application/json')

    cnt = 1
    if "cnt" in req_body:
        cnt = req_body["cnt"]

    ###
    # If testing loopback, sniff before send clears sniffers first.
    # Otherwise, clear sniffers now.
    ##
    if "loopback" not in req_body or req_body["loopback"] != "true":
        clearPrevSniffers()

    if "inPacket" in req_body:
        sendProc = multiprocessing.Process(target=send_packet_func,
                kwargs={'target_iface':target_iface,
                'pkt': base64.b64decode(req_body["inPacket"]),
                'cnt':cnt})

        sendProc.start()
        sendProc.join(waitMilliSec / 1000)
        if sendProc.is_alive():
            api.logger.warn(f"sendProc is not working")
            sendProc.terminate()

        return Response(response=json.dumps([{"result": f"success"}]),
                status=200, mimetype='application/json')

    src = req_body["src"]
    dst = req_body["dst"]

    criteria = []
    ipProto = 17
    if "criteria" in req_body:
        criteria = req_body["criteria"]

        for criterion in criteria:
            if ("type" in criterion) and (criterion["type"] == "IP_PROTO"):
                ipProto = criterion["protocol"]

    # TODO: set ethernet address
    ethPkt = Ether()
    if "ethDst" in req_body:
        ethPkt = Ether(dst=req_body["ethDst"])

    if ipProto == 6:
        # work-around
        pkt = ethPkt/IP(src=src, dst=dst)/TCP(sport=50000, dport=1234)
    elif ipProto == 17:
        pkt = ethPkt/IP(src=src, dst=dst)/UDP(sport=50000, dport=1234)
    elif ipProto == 1:
        pkt = ethPkt/IP(src=src, dst=dst)/ICMP()
    elif ipProto == 0x84:
        pkt = ethPkt/IP(src=src, dst=dst)/SCTP()
    else:
        pkt = ethPkt

    sendProc = multiprocessing.Process(target=send_packet_func,
            kwargs={'target_iface':target_iface,
            'pkt':pkt,
            'cnt':cnt})

    sendProc.start()
    sendProc.join(waitMilliSec / 1000)
    if sendProc.is_alive():
        api.logger.warn(f"sendProc is not working")
        sendProc.terminate()

    api.logger.info(f"[POST://send] {src} to {dst}")

    return Response(response=json.dumps([{"src": src, "dst": dst, "result": "success"}]), status=200, mimetype='application/json')

@api.route('/sniff_bddp', methods=['POST'])
def sniff_bddp():
    global iface
    req_body = request.get_json()

    target_iface = iface
    if target_iface not in netifaces.interfaces():
        req_body["result"] = "fail"
        api.logger.error(f"{target_iface} is not in host")

        return Response(response=req_body, status=404, mimetype='application/json')

    pkt = sniff(iface=target_iface, count=1, filter="ether proto 0x8942")

    resp_body = {}
    resp_body["inPacket"] = base64.b64encode(raw(pkt[0])).decode("ascii")

    return Response(response=json.dumps(resp_body), status=200)

@api.route('/sniff_lldp', methods=['POST'])
def sniff_lldp():
    global iface
    req_body = request.get_json()

    target_iface = iface
    if target_iface not in netifaces.interfaces():
        req_body["result"] = "fail"
        api.logger.error(f"{target_iface} is not in host")

        return Response(response=req_body, status=404, mimetype='application/json')

    pkt = sniff(iface=target_iface, count=1, filter="ether proto 0x88cc")

    resp_body = {}
    resp_body["inPacket"] = base64.b64encode(raw(pkt[0])).decode("ascii")

    return Response(response=json.dumps(resp_body), status=200)


@api.route('/sniff', methods=['POST'])
def sniff_host():
    global iface, sniffThreadList, packetQueue, packetWorker
    global sniffWaitCond, sniffStatus, finalResult
    req_body = request.get_json()

    # read target_iface
    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    # Fail if no target_iface
    if target_iface not in netifaces.interfaces():
        req_body["result"] = "fail"
        api.logger.error(f"{target_iface} is not in host")

        return Response(response=req_body, status=404, mimetype='application/json')

    # If loopback, clear prev sniffers first.
    if "loopback" in req_body and req_body["loopback"] == "true":
        clearPrevSniffers()

    # Stop existing one first
    seq = req_body["seq"]
    key = req_body["key"]
    try:
        tmpThread = sniffThreadList[key + seq]
        api.logger.info(f"Stop sniffThread with {key}:{seq}")
        sniffThreadList.pop(key + seq)
        tmpThread.stop()
    except KeyError as ke:
        ''' Not Found '''
    except Scapy_Exception as se:
        ''' Not running '''

    if packetWorker is not None and packetWorker.is_alive():
        # Stop stuck packetWorker
        api.logger.warn('Stop previous packetWorker')
        packetQueue.put({'R':True})
        packetWorker.join()
        api.logger.info('Stopped')

    # Create thread
    thread = None
    packetQueue = None
    packetWorker = None
    finalResult = None
    sniffStatus = SniffStatus.INIT

    if "outPacket" in req_body:
        expPacket = req_body["outPacket"]
        packetQueue = Queue()
        if len(expPacket) == 0:
            # SNIFF no packet
            # XXX: How could it differentiate noisy packets?
            thread = AsyncSniffer(iface=target_iface, stop_filter=lambda x : putPacketInQueue(x, packetQueue),
                    timeout=2, started_callback=markSniffing)

            packetWorker = threading.Thread(target=stop_filter_no_packet,
                    args=(packetQueue, req_body))
            packetWorker.setDaemon(True)
            packetWorker.start()

        else:
            expBytes = base64.b64decode(req_body["outPacket"])
            maskBytes = base64.b64decode(req_body["outPacketMask"])
            expMaskedBytes = bytes([a & b for a, b in zip(expBytes[::-1], maskBytes[::-1])][::-1])
            thread = AsyncSniffer(iface=target_iface, stop_filter=lambda x : putPacketInQueue(x, packetQueue),
                    timeout=2, started_callback=markSniffing)

            packetWorker = threading.Thread(target=stop_filter_by_packet,
                    args=(packetQueue, req_body, expMaskedBytes, maskBytes))
            packetWorker.setDaemon(True)
            packetWorker.start()

    else:
        src = req_body["src"]
        dst = req_body["dst"]

        criteria = []
        ipProto = 17
        if "criteria" in req_body:
            criteria = req_body["criteria"]

            for criterion in criteria:
                if ("type" in criterion) and (criterion["type"] == "IP_PROTO"):
                    ipProto = criterion["protocol"]

        filterStr="ip proto " + str(ipProto) + " and src " + src + " and dst " + dst

        packetQueue = Queue()
        thread = AsyncSniffer(iface=target_iface, stop_filter=lambda x : putPacketInQueue(x, packetQueue),
                filter=filterStr, count=1, timeout=2,
                started_callback=markSniffing)
        packetWorker = threading.Thread(target=stop_filter_by_string,
                args=(packetQueue, ipProto, req_body))
        packetWorker.setDaemon(True)
        packetWorker.start()


    api.logger.debug(f"[POST://sniff] at {target_iface}")

    with sniffWaitCond:
        sniffThreadList.update({key+seq:thread})
        thread.start()
        # markSniffing() - callback - will set SniffStatus.WAITING
        while sniffStatus == SniffStatus.INIT:
            sniffWaitCond.wait()

    req_body["result"] = "success"

    return Response(response=json.dumps(req_body), status=200,
            mimetype='application/json')

@api.route('/stopsniff', methods=['POST'])
def stop_sniff_host():
    global iface, sniffThreadList, packetQueue, packetWorker, sniffStatus, sniffWaitCond, finalResult

    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    with sniffWaitCond:
        while sniffStatus == SniffStatus.CALLBACK:
            sniffWaitCond.wait()

        if sniffStatus == SniffStatus.WAITING:
            sniffStatus = SniffStatus.STOPPING

    # STOPPED or STOPPING

    try:
        # stop sniffThread first
        tmpThread = sniffThreadList[key + seq]
        api.logger.info(f"Stop sniffThread with {key}:{seq}")
        sniffThreadList.pop(key + seq)
        tmpThread.stop()
    except KeyError as ke:
        ''' Not Found '''
    except Scapy_Exception as se:
        ''' Not running '''

    # If packetQueue exists, wait worker until queue becomes empty
    if packetQueue is not None:
        packetQueue.put({'R':True})

    resp = None
    with sniffWaitCond:
        if sniffStatus == SniffStatus.STOPPED:
            # (1) Timeout
            resp = Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
                    status=204, mimetype='application/json')
        else:
            # (2) Get result
            retJson = {"seq": seq, "key": key}
            retStatus = 204
            if finalResult is not None:
                retJson = copy.deepcopy(finalResult)
                api.logger.info(f"get result from packetWorker: {retJson}")
                retStatus = 200

            resp = Response(response=json.dumps(retJson),
                    status=retStatus, mimetype='application/json')

            sniffStatus = SniffStatus.STOPPED
        return resp


@api.route('/genreplay', methods=['POST'])
def gen_tcpreplay():
    global iface, replayProcList
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    # TODO: make src and dst as lists
    src = req_body["src"]
    dst = req_body["dst"]

    ''' TODO: manage tcpreplay process by seq+key '''
    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    if key + seq in replayProcList:
        replayProc = replayProcList.pop(key + seq)
        os.killpg(os.getpgid(replayProc.pid), signal.SIGTERM)
    replayProcList[key + seq] = exec_tcpreplay(src, dst, network_name(target_iface))

    return Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
            status=200, mimetype='application/json')

@api.route('/stopreplay', methods=['POST'])
def stop_tcpreplay():
    ''' kill tcpreplay '''
    global replayProcList
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    if key + seq not in replayProcList:
        return Response(response=json.dumps([{"seq": seq, "key": key, "result": "no tcpreplay process"}]),
           status=404, mimetype='application/json')

    replayProc = replayProcList.pop(key + seq)
    api.logger.info(f"Try to kill {replayProc.pid}")
    os.killpg(os.getpgid(replayProc.pid), signal.SIGTERM)
    tmpOut, tmpErr = replayProc.communicate()

    return Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
            status=200, mimetype='application/json')


# @app.route('/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
# def handle_request(url):
#     return RestHandler(request).handle_proxy()
#
# class RestHandler(object):
#
#     def __init__(self, request):
#         LOG.debug(f'HTTP request: {request}')
#         self.req = request
#
#     def handle_proxy(self):
#         path = 'ping/%s' % ()
#         try:
#             return self._handle_proxy(self.req)
#         except Exception as E:
#             LOG.error(f'exception happens in _handle_proxy: {str(E)}')
#             return 'failed', INTERNAL_SERVER_ERROR
#
#     def _hande_proxy(self, req):


class DpDaemon(Daemon):
    def __init__(self, options, pidfile, processname=''):
        super(DpDaemon, self).__init__(pidfile, processname,
                stdout=options.logfile, stderr=options.logfile)
        global iface, pcap, pps, ppsMulti, ttsFilePath
        iface = options.iface
        pcap = options.pcap
        pps = options.pps
        ppsMulti = options.ppsMulti
        self.callback = options.callback

        handler = logging.FileHandler(options.logfile)
        api.logger.addHandler(handler)
        api.logger.setLevel(logging.DEBUG)
        ttsFilePath = options.logfile

    def run(self):
        thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        thread.start()

        if self.callback is not None:
            try:
                h = httplib2.Http(timeout=5)
                resp, content = h.request(self.callback, method='GET')
            except Exception:
                ''' connection fails '''

class DpFgDaemon():
    def __init__(self, options):
        global iface, pcap, pps, ppsMulti, ttsFilePath
        iface = options.iface
        pcap = options.pcap
        pps = options.pps
        ppsMulti = options.ppsMulti
        self.callback = options.callback

        handler = logging.FileHandler(options.logfile)
        api.logger.addHandler(handler)
        api.logger.setLevel(logging.DEBUG)
        ttsFilePath = options.logfile

    def start(self):
        thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        thread.start()

        if self.callback is not None:
            try:
                h = httplib2.Http(timeout=5)
                resp, content = h.request(self.callback, method='GET')
            except Exception:
                ''' connection fails '''

    def stop(self):
        ''' Do nothing '''

    def restart(self):
        ####### TODO #######
        ''' Do nothing '''

    def status(self):
        ''' Do nothing '''
