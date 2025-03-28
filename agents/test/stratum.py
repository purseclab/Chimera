# coding=utf-8
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

'''
This module contains a switch class for Mininet: StratumBmv2Switch

Prerequisites
-------------
1. Docker- mininet+stratum_bmv2 image:
$ cd stratum
$ docker build -t <some tag> -f tools/mininet/Dockerfile .

Usage
-----
From withing the Docker container, you can run Mininet using the following:
$ mn --custom /root/stratum.py --switch stratum-bmv2 --controller none

Advanced Usage
--------------
You can use this class in a Mininet topology script by including:

from stratum import ONOSStratumBmv2Switch

You will probably need to update your Python path. From within the Docker image:

PYTHONPATH=$PYTHONPATH:/root ./<your script>.py

Notes
-----
This code has been adapted from the ONOSBmv2Switch class defined in the ONOS project
(tools/dev/mininet/bmv2.py).

'''

import json
import multiprocessing
import os, signal
import socket
import threading
import time

# TODO: multiple-device support
from itertools import takewhile
import p4runtime_sh.shell as p4rt_sh
from p4runtime_sh.context import P4Type

from mininet.log import warn
from mininet.node import Switch, Host

DEFAULT_NODE_ID             = 1
DEFAULT_CPU_PORT            = 255
DEFAULT_PIPECONF            = "org.onosproject.pipelines.basic"
STRATUM_HOME                = os.getenv('STRATUM_HOME')
STRATUM_AGENT               = f"{STRATUM_HOME}/stratum-agent"
STRATUM_GNMI_CLI            = f"{STRATUM_HOME}/gnmi_cli"
STRATUM_BMV2                = f"{STRATUM_HOME}/stratum_bmv2"
STRATUM_INIT_PIPELINE       = '/root/dummy.json'
BMV2_LOG_LINES              = 5
MAX_CONTROLLERS_PER_NODE    = 10

def writeToFile(path, value):
    with open(path, "w") as f:
        f.write(str(value))


def pickUnusedPort():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    addr, port = s.getsockname()
    s.close()
    return port

def split_id_and_name_in_proto_str(proto_line):
    if not proto_line.endswith('")'):
        return proto_line

    proto_spaces = ''.join(takewhile(str.isspace, proto_line))
    proto_words = proto_line.strip().split(' ')

    if len(proto_words) <= 1:
        return proto_line
    elif not proto_words[0].endswith('_id:'):
        return proto_line

    proto_type = proto_words[0][:-4]

    # 1) original line with ID
    new_proto = ''
    last_idx = len(proto_words) - 1
    for i in range(0, last_idx):
        if i == 0:
            new_proto += f'{proto_spaces}'
        else:
            new_proto += ' '
        new_proto += f'{proto_words[i]}'

    # 2) new line with NAME
    new_proto += f'\n{proto_spaces}{proto_type}_name: {proto_words[last_idx][1:-1]}'

    return new_proto

def watchdog(sw):
    try:
        writeToFile(sw.keepaliveFile,
                    "Remove this file to terminate %s" % sw.name)
        while True:
            if StratumBmv2Switch.mininet_exception == 1 \
                    or not os.path.isfile(sw.keepaliveFile):
                sw.stop()
                return
            if sw.stopped:
                return
            if sw.bmv2popen.poll() is None:
                # All good, no return code, still running.
                time.sleep(1)
            else:
                warn("\n*** WARN: switch %s died ☠️ \n" % sw.name)
                sw.printLog()
                print("-" * 80 + "\n")
                # Close log file, set as stopped etc.
                sw.stop()
                return
    except Exception as e:
        warn("*** ERROR: " + e.message)
        sw.stop()

class StratumBmv2Switch(Switch):
    # Shared value used to notify to all instances of this class that a Mininet
    # exception occurred. Mininet exception handling doesn't call the stop()
    # method, so the mn process would hang after clean-up since Bmv2 would still
    # be running.
    mininet_exception = multiprocessing.Value('i', 0)

    nextGrpcPort = 50001

    def __init__(self, name, json=STRATUM_INIT_PIPELINE, loglevel="warn",
                 cpuport=DEFAULT_CPU_PORT, pipeconf=DEFAULT_PIPECONF,
                 ipAddr="localhost",
                 onosdevid=None, adminstate=True,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.grpcPort = StratumBmv2Switch.nextGrpcPort
        StratumBmv2Switch.nextGrpcPort += 1
        self.cpuPort = cpuport
        self.json = json
        self.loglevel = loglevel
        self.ipAddr = ipAddr
        self.tmpDir = '/tmp/%s' % self.name
        self.logfile = '%s/stratum_bmv2.log' % self.tmpDir
        self.netcfgFile = '%s/onos-netcfg.json' % self.tmpDir
        self.chassisConfigFile = '%s/chassis-config.txt' % self.tmpDir
        self.pipeconfId = pipeconf
        self.longitude = kwargs['longitude'] if 'longitude' in kwargs else None
        self.latitude = kwargs['latitude'] if 'latitude' in kwargs else None
        if onosdevid is not None and len(onosdevid) > 0:
            self.onosDeviceId = onosdevid
        else:
            # The "device:" prefix is required by ONOS.
            self.onosDeviceId = "device:%s" % self.name
        self.nodeId = DEFAULT_NODE_ID
        self.logfd = None
        self.bmv2popen = None
        self.is_p4rt_setup = False
        self.stopped = True
        # In case of exceptions, mininet removes *.out files from /tmp. We use
        # this as a signal to terminate the switch instance (if active).
        self.keepaliveFile = '/tmp/%s-watchdog.out' % self.name
        self.adminState = "ENABLED" if adminstate else "DISABLED"

        self.gnmiCliArgs = [STRATUM_GNMI_CLI,
            '--grpc-addr',
            '%s:%d' % (self.ipAddr, self.grpcPort),
        ]

        self.intfToPortMapCache = {}

        # Remove files from previous executions
        self.cleanupTmpFiles()
        os.mkdir(self.tmpDir)

    def getOnosNetcfg(self):
        basicCfg = self.getOnosNetcfgObject()
        netcfg = {
            "devices": {
                self.onosDeviceId: basicCfg
            }
        }

        return netcfg

    def getOnosNetcfgObject(self):
        basicCfg = {
            "managementAddress": "grpc://%s:%d?device_id=%d" % (
                self.ipAddr, self.grpcPort, self.nodeId),
            "driver": "stratum-bmv2",
            "pipeconf": self.pipeconfId
        }

        if self.longitude and self.latitude:
            basicCfg["longitude"] = self.longitude
            basicCfg["latitude"] = self.latitude

        netcfg = {
            "basic": basicCfg
        }

        return netcfg


    def getChassisPortConfig(self, intfName, intfNo):
        return """singleton_ports {{
  id: {intfNumber}
  name: "{intfName}"
  slot: 1
  port: {intfNumber}
  channel: 1
  speed_bps: 10000000000
  config_params {{
    admin_state: ADMIN_STATE_{adminState}
  }}
  node: {nodeId}
}}\n""".format(intfName=intfName, intfNumber=intfNo, nodeId=self.nodeId, adminState=self.adminState)


    def getChassisConfig(self):
        config = """description: "stratum_bmv2 {name}"
chassis {{
  platform: PLT_P4_SOFT_SWITCH
  name: "{name}"
}}
nodes {{
  id: {nodeId}
  name: "{name} node {nodeId}"
  slot: 1
  index: 1
}}\n""".format(name=self.name, nodeId=self.nodeId)

        intf_number = 1
        for intf_name in self.intfNames():
            if intf_name == 'lo':
                continue
            config = config + self.getChassisPortConfig(intf_name, intf_number)
            intf_number += 1

        return config

    def start(self, controllers):

        if not self.stopped:
            warn("*** %s is already running!\n" % self.name)
            return

        writeToFile("%s/grpc-port.txt" % self.tmpDir, self.grpcPort)
        with open(self.chassisConfigFile, 'w') as fp:
            fp.write(self.getChassisConfig())
        with open(self.netcfgFile, 'w') as fp:
            json.dump(self.getOnosNetcfg(), fp, indent=2)

        self.is_cov_running = os.path.isfile(STRATUM_AGENT)
        self.trace_bits_file = f'{self.tmpDir}/trace-bits'

        args = []
        my_env = os.environ.copy()
        if self.is_cov_running:
            args.extend([STRATUM_AGENT,
                    '-o %s/code-output' % self.tmpDir,
                    '-g %s' % self.trace_bits_file,
                    '--'])
            my_env['AFL_PRELOAD'] = f"{my_env['ASAN_SO_PATH']} {my_env['AFL_PRELOAD']}"

        args.extend([
            STRATUM_BMV2,
            '-device_id=%d' % self.nodeId,
            '-chassis_config_file=%s' % self.chassisConfigFile,
            '-forwarding_pipeline_configs_file=%s/pipe.txt' % self.tmpDir,
            '-persistent_config_dir=%s' % self.tmpDir,
            '-initial_pipeline=%s' % self.json,
            '-cpu_port=%s' % self.cpuPort,
            '-external_stratum_urls=%s:%d' % (self.ipAddr, self.grpcPort),
            '-local_stratum_url=localhost:%d' % pickUnusedPort(),
            '-max_num_controllers_per_node=%d' % MAX_CONTROLLERS_PER_NODE,
            '-write_req_log_file=%s/write-reqs.txt' % self.tmpDir,
            '-bmv2_log_level=%s' % self.loglevel,
        ])

        cmd_string = " ".join(args)

        try:
            # Write cmd_string to log for debugging.
            self.logfd = open(self.logfile, "w")
            self.logfd.write(cmd_string + "\n\n" + "-" * 80 + "\n\n")
            self.logfd.flush()

            print(f"Run preload with {my_env['AFL_PRELOAD']}")
            self.bmv2popen = self.popen(cmd_string, stdout=self.logfd, stderr=self.logfd,
                    cwd=STRATUM_HOME, env=my_env)
            print("⚡️ %s @ %d" % ("STRATUM_BMV2", self.grpcPort))

            # We want to be notified if stratum_bmv2 quits prematurely...
            self.stopped = False
            threading.Thread(target=watchdog, args=[self]).start()

        except Exception:
            StratumBmv2Switch.mininet_exception = 1
            self.stop()
            self.printLog()
            raise

    def getPortNo(self, intfName):
        # TODO: clear port-intf cache while changing topology
        if intfName in self.intfToPortMapCache:
            return self.intfToPortMapCache[intfName]

        gnmiCliCmd = " ".join(self.gnmiCliArgs + [
            'get',
            '/interfaces/interface[name=%s]/state/ifindex' % intfName
        ])

        retStrs = self.cmdPrint( gnmiCliCmd ).splitlines()

        hasResp = False
        prevStr = ""
        for retStr in retStrs:
            if retStr.lstrip().startswith("RESPONSE"):
                hasResp = True
                continue

            if not hasResp:
                continue

            if retStr.lstrip().startswith("uint_val") and \
                    prevStr.lstrip().startswith("val {"):
                # skip 'uint_val: '
                portNo = int(retStr.lstrip()[10:])
                self.intfToPortMapCache[intfName] = portNo
                return portNo

            prevStr = retStr

        return -1

    def getIntfFromPortNo(self, portNo):
        intfName = f"{self.name}-eth{portNo}"

        if self.getPortNo(intfName) == portNo:
            return intfName

        return None

    def enable_intf(self, intfName):
        gnmiCliCmd = " ".join(self.gnmiCliArgs + [
            'set',
            '/interfaces/interface[name=%s]/config/enabled' % intfName,
            '--bool_val',
            'true'
        ])
        self.cmd(gnmiCliCmd)

    def disable_intf(self, intfName):
        gnmiCliCmd = " ".join(self.gnmiCliArgs + [
            'set',
            '/interfaces/interface[name=%s]/config/enabled' % intfName,
            '--bool_val',
            'false'
        ])
        self.cmd(gnmiCliCmd)


    # attach interface by fixing file and updating via gnmi
    def attach(self, intfName, portNo, mtu=1500):
        ''' attach '''
        if self.getPortNo(intfName) < 0:
            # write self.chassisConfigFile
            with open(self.chassisConfigFile, 'a') as fp:
                fp.write(self.getChassisPortConfig(intfName, portNo))

            trial = 10
            while trial > 0:
                gnmiCliCmd = " ".join(self.gnmiCliArgs + [
                    '--replace',
                    '--bytes_val_file',
                    self.chassisConfigFile,
                    'set',
                    '/'
                ])
                self.cmd(gnmiCliCmd)

                if self.getPortNo(intfName) == portNo:
                    break

                time.sleep(0.05)
                trial -= 1

        else:
            self.enable_intf(intfName)

        self.cmd( 'ifconfig', intfName, 'mtu', mtu, 'up' )

    def detach(self, intfName):
        ''' detach '''
        if self.getPortNo(intfName) < 0:
            return

        self.disable_intf(intfName)

    def printLog(self):
        if os.path.isfile(self.logfile):
            print("-" * 80)
            print("%s log (from %s):" % (self.name, self.logfile))
            with open(self.logfile, 'r') as f:
                lines = f.readlines()
                if len(lines) > BMV2_LOG_LINES:
                    print("...")
                for line in lines[-BMV2_LOG_LINES:]:
                    print(line.rstrip())

    def cleanupTmpFiles(self):
        self.cmd("rm -rf %s" % self.tmpDir)

    def stop(self, deleteIntfs=True):
        """Terminate switch."""
        self.p4rt_teardown()

        self.stopped = True
        if self.bmv2popen is not None:
            if self.is_cov_running:
                print(f'kill {STRATUM_AGENT} ({self.bmv2popen.pid})')
                os.kill(self.bmv2popen.pid, signal.SIGTERM)

            elif self.bmv2popen.poll() is None:
                print(f'terminate ({self.bmv2popen.pid})')
                self.bmv2popen.terminate()
                self.bmv2popen.wait()
            self.bmv2popen = None
        if self.logfd is not None:
            self.logfd.close()
            self.logfd = None
        Switch.stop(self, deleteIntfs)

    def getPid(self):
        if self.bmv2popen is None:
            return 0
        return self.bmv2popen.pid

    def getTraceBitsFile(self):
        if self.is_cov_running:
            return self.trace_bits_file

        return ""

    def p4rt_connect(self):
        if self.is_p4rt_setup:
            return False

        p4rt_sh.setup(device_id=self.nodeId,
                grpc_addr=f'{self.ipAddr}:{self.grpcPort}',
                election_id=(0, 1))

        self.is_p4rt_setup = True
        return True

    def p4rt_teardown(self):
        if self.is_p4rt_setup:
            p4rt_sh.teardown()
            self.is_p4rt_setup = False

    def get_current_rules(self):
        if not self.is_p4rt_setup:
            self.p4rt_connect()

        table_list = p4rt_sh.P4Objects(P4Type.table)

        proto_str = ''
        # for loop: each table
        for table in table_list:
            te_list = p4rt_sh.TableEntry(table.name).read()

            # for loop: each table entry (te)
            for te in te_list:
                te_str=f'{te}'

                # for loop: each line of te proto
                te_new_str=''
                for line in te_str.splitlines():
                    te_new_str += '\n' + split_id_and_name_in_proto_str(line.replace('\\\\', '\\'))

                if len(proto_str) == 0:
                    proto_str += 'entities : ['
                else:
                    proto_str += ','

                proto_str += f'\n{{\ntable_entry {{\n{te_new_str}\n}}\nis_default_entry: 1\n}}'

        if len(proto_str) > 0:
            proto_str += '\n]'
        return proto_str


class RemoteStratumSwitch(StratumBmv2Switch):

    def __init__(self, name, loglevel="warn", chassisConfigFile=None,
                 cpuport=DEFAULT_CPU_PORT, grpcPort=50000,
                 ipAddr="localhost", portNum=0,
                 pipeconf=DEFAULT_PIPECONF, onosdevid=None, adminstate=True,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.tmpDir = '/tmp/%s' % self.name
        self.cpuPort = cpuport
        self.grpcPort = grpcPort
        self.pipeconfId = pipeconf
        self.nodeId = DEFAULT_NODE_ID
        self.ipAddr = ipAddr
        self.bmv2popen = None
        self.is_p4rt_setup = False
        self.longitude = kwargs['longitude'] if 'longitude' in kwargs else None
        self.latitude = kwargs['latitude'] if 'latitude' in kwargs else None
        self.chassisConfigFile = chassisConfigFile
        self.portNum = portNum
        self.intfToPortMapCache = {}

        if onosdevid is not None and len(onosdevid) > 0:
            self.onosDeviceId = onosdevid
        else:
            # The "device:" prefix is required by ONOS.
            self.onosDeviceId = "device:%s" % self.name

        self.cleanupTmpFiles()
        os.mkdir(self.tmpDir)

        self.gnmiCliArgs = [STRATUM_GNMI_CLI,
            '--grpc-addr',
            '%s:%d' % (self.ipAddr, self.grpcPort),
        ]


    def getChassisConfig(self):
        configString = ""
        if self.chassisConfigFile is None or \
            not os.path.isfile(self.chassisConfigFile):
                return ""

        try:
            with open(self.chassisConfigFile, "r") as f:
                configString = f.read()
        except IOError:
            return ""

        return configString

    def start(self, controllers):
        self.is_cov_running = False
        self.trace_bits_file = None
        writeToFile("%s/grpc-port.txt" % self.tmpDir, self.grpcPort)
        self.stopped = True

    def stop(self, deleteIntfs=True):
        self.p4rt_teardown()
        Switch.stop(self, deleteIntfs)

    def cleanupTmpFiles(self):
        self.cmd("rm -rf %s" % self.tmpDir)

    def getIntfFromPortNo(self, portNo):
        if portNo not in self.intfs.keys():
            return None

        intfName = self.intfs[portNo].name

        if self.getPortNo(intfName) == portNo:
            return intfName

        return None


class NoOffloadHost(Host):
    def __init__(self, name, inNamespace=True, **params):
        Host.__init__(self, name, inNamespace=inNamespace, **params)

    def config(self, **params):
        r = super(Host, self).config(**params)
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" \
                  % (self.defaultIntf(), off)
            self.cmd(cmd)
        return r

class NoIpv6OffloadHost(NoOffloadHost):
    def __init__(self, name, inNamespace=True, **params):
        NoOffloadHost.__init__(self, name, inNamespace=inNamespace, **params)

    def config(self, **params):
        r = super(NoOffloadHost, self).config(**params)
        self.cmd("sysctl net.ipv6.conf.%s.disable_ipv6=1" % (self.defaultIntf()))
        return r


# Exports for bin/mn
switches = {'stratum-bmv2': StratumBmv2Switch}

hosts = {
    'no-offload-host': NoOffloadHost,
    'no-ipv6-host': NoIpv6OffloadHost
}
