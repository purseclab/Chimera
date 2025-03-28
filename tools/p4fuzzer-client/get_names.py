#!/bin/python3

from optparse import OptionParser
import grpc, sys
import p4testgen_pb2
import p4testgen_pb2_grpc
from client import p4testgen_get_statement

def orBytes(abytes, bbytes):
    return bytes([a | b for a, b in zip(abytes[::-1], bbytes[::-1])][::-1])

def andBytes(abytes, bbytes):
    return bytes([a & b for a, b in zip(abytes[::-1], bbytes[::-1])][::-1])

def printDiff(stub, abytes, bbytes):
    if abytes != bbytes:
        idx = 1
        skipped = False
        for i in range(0, len(abytes)):
            byte_diff = abytes[i] ^ bbytes[i]
            if byte_diff != 0:
                for b in range(7, -1, -1):
                    req_idx = idx + 7 - b
                    if (byte_diff >> b) & 1:
                        stmt = p4testgen_get_statement(stub, req_idx)
                        if (abytes[i] >> b) & 1:
                            print(f"DIFF ({req_idx}): < {stmt}")
                        else:
                            print(f"DIFF ({req_idx}): > {stmt}")
            idx += 8

def Main(stub, options):
    req = p4testgen_pb2.P4NameRequest()
    req.entity_type = 0
    resp = stub.GetP4Name(req)
    for tableName in resp.name:
        req.entity_type = 1
        req.target = tableName

        print(f"req {tableName}")
        resp = stub.GetP4Name(req)
        print("[MATCH] " + req.target)
        print(resp.name)
        print(resp.type)
        print(resp.bit_len)

        req.entity_type = 2
        req.target = tableName

        resp = stub.GetP4Name(req)
        print("[ACTION] " + req.target)
        print(resp.name)
        print(resp.bit_len)

        for actionName in resp.name:
            req.entity_type = 3
            req.target = actionName

            resp = stub.GetP4Name(req)
            print("[PARAM] " + req.target)
            print(resp.name)
            print(resp.bit_len)
    for i in range(0, 4):
        req.entity_type = i
        req.target = "a"

        resp = stub.GetP4Name(req)
        print("[ACTION] " + req.target)
        print(resp.name)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", metavar="FILE",
            help="specify input file")
    parser.add_option("-x", "--ip", dest="ip", default="localhost",
            help="GRPC server IP address", metavar="IP")
    parser.add_option("-y", "--port", dest="port", default=50051,
            help="GRPC server port", metavar="PORT", type="int")
    parser.add_option("-c", "--covSize", dest="covSize", metavar="INT",
            help="specify total statements of the program", type="int", default=1)
    parser.add_option("-n", "--num", dest="num", metavar="INT",
            help="specify number of file line", type="int", default=0)

    (options, args) = parser.parse_args()

    with grpc.insecure_channel(f"{options.ip}:{options.port}") as channel:
        stub = p4testgen_pb2_grpc.P4FuzzGuideStub(channel)
        Main(stub, options)
