import os, sys
import logging
import random
from os import walk

import grpc
import p4testgen_pb2
import p4testgen_pb2_grpc
from google.protobuf.text_format import Parse, MessageToString
from optparse import OptionParser

def getHitCount(bb):
    cnt = 0
    for cb in bb:
        cnt += bin(cb).count("1")
    return cnt

def getHexString(bb):
    return ''.join('{:02x}'.format(x) for x in bb)

def p4testgen_record_coverage(stub, inputFile, outputFile):
    req = p4testgen_pb2.P4CoverageRequest()

    isInit = False
    with open(inputFile, 'rb') as f:
        try:
            req = Parse(f.read(), p4testgen_pb2.P4CoverageRequest())
            isInit = True
        except Exception as e:
            print(e)

    if not isInit:
        with open(inputFile, 'rb') as f:
            try:
                req.device_id = "s1"
                req.test_case.MergeFrom(Parse(f.read(), p4testgen_pb2.TestCase()))
                isInit = True
            except Exception as e:
                print(e)

    if not isInit:
        sys.exit(2)

    print(f"Received stmt: {getHexString(req.test_case.stmt_cov_bitmap)} ({getHitCount(req.test_case.stmt_cov_bitmap)})")
    response = stub.RecordP4Testgen(req)

    if outputFile is not None:
        with open(outputFile, 'w') as f:
            # exclude non-matched rules
            if options.removeInvalidRule:
                newEntities = []
                for entity in response.test_case.entities:
                    if entity.table_entry.matched_idx < 0:
                        continue
                    newEntities.append(entity)
                del response.test_case.entities[:]
                response.test_case.entities.extend(newEntities)
            f.write(MessageToString(response.test_case, as_utf8=True))


    print("Record %s Coverage: %s/%d (stmt) and %s/%d (action)" %
            (req.device_id, response.test_case.stmt_cov_bitmap, response.test_case.stmt_cov_size,
             response.test_case.action_cov_bitmap, response.test_case.action_cov_size))
    if len(response.test_case.expected_output_packet) > 0:
        if len(req.test_case.expected_output_packet) > 0:
            print(f"Output to {req.test_case.expected_output_packet[0].port} vs.", end =" ")
        print(f"Output to {response.test_case.expected_output_packet[0].port}")
        if options.repeatCnt <= 1:
            print(f"{response.test_case.expected_output_packet[0].packet}")

    for entity in response.test_case.entities:
        if entity.table_entry is None:
            continue

        print(f"{entity.table_entry.is_valid_entry} {entity.table_entry.matched_idx}")

    bitmap = response.test_case.stmt_cov_bitmap
    actionBitmap = response.test_case.action_cov_bitmap
    print("Get %s Coverage: %d/%d rules, %d/%d stmt (%s), and %d/%d action (%s)" %
            (req.device_id, len(response.test_case.entities), response.test_case.table_size,
             getHitCount(bitmap), response.test_case.stmt_cov_size, getHexString(bitmap),
             getHitCount(actionBitmap), response.test_case.action_cov_size, getHexString(actionBitmap)))

    # PATH TEST
    for respCov in response.test_case.path_cov:
        for reqCov in req.test_case.path_cov:
            if reqCov.block_name == respCov.block_name:
                ''' found '''
                if reqCov.path_val != respCov.path_val:
                    print(f"Invalid path val in {reqCov.block_name}: 0x{reqCov.path_val.hex()} vs. 0x{respCov.path_val.hex()}")
                    return
                if reqCov.path_size != respCov.path_size:
                    print(f"Invalid path size in {reqCov.block_name}: 0x{respCov.path_size.hex()}")
                    return
                break;

def skip_test_case(testCase):
    return False

    for entity in testCase.entities:
        if entity.table_entry is None:
            continue

        if "wcmp" in entity.table_entry.table_name:
            return True


def p4testgen_record_coverage_wo_dev(options, stub, inputPath, inputFile):
    req = p4testgen_pb2.P4CoverageRequest()

    with open(inputPath + "/" + inputFile, 'rb') as f:
        try:
            req.device_id = inputFile
            req.test_case.MergeFrom(Parse(f.read(), p4testgen_pb2.TestCase()))
        except Exception as e:
            print(e)
            if options.ignoreErr:
                return False, True
            else:
                sys.exit(2)

    if skip_test_case(req.test_case):
        return False, True

    try:
        resp = stub.RecordP4Testgen(req)
    except Exception as e:
        print(e)
        if options.ignoreErr:
            return False, True
        else:
            sys.exit(2)

    if options.output is not None:
        with open(options.output + "/" + inputFile, 'w') as f:
            f.write(MessageToString(resp.test_case, as_utf8=True))
        return True, True

    resp_bytes = resp.test_case.stmt_cov_bitmap
    req_bytes = req.test_case.stmt_cov_bitmap

    # COVERAGE
    if resp_bytes != req_bytes:
        print(f"response ({getHitCount(resp_bytes)}) != req ({getHitCount(req_bytes)})")
        idx = 1
        if options.ignoreDiffCov:
            return False, True

        for i in range(0, len(resp_bytes)):
            byte_diff = resp_bytes[i] ^ req_bytes[i]
            if byte_diff != 0:
                for b in range(7, -1, -1):
                    if (byte_diff >> b) & 1:
                        req_idx = idx + 7 - b
                        stmt = p4testgen_get_statement(stub, req_idx)
                        if (resp_bytes[i] >> b) & 1:
                            print(f"DIFF ({req_idx}): + {stmt}")
                        else:
                            print(f"DIFF ({req_idx}): - {stmt}")

            idx += 8

        return False, False

    # OUTPUT TEST
    if len(resp.test_case.expected_output_packet) != 0:
        reqOutput = req.test_case.expected_output_packet[0]
        respOutput = resp.test_case.expected_output_packet[0]

        if reqOutput.port != respOutput.port:
            print(f"DIFF (Output Port): {reqOutput.port} vs. {respOutput.port}")
            return False, False
        else:
            print(f"Same output port {respOutput.port}")

        if reqOutput.packet!= respOutput.packet:
            print(f"Diff output packet: {respOutput.packet}")
            print(f"Diff output packet: {reqOutput.packet}")
            return False, False

    # VERIFY TEST
    for entity in resp.test_case.entities:
        if entity.table_entry is None:
            continue

        if entity.table_entry.is_valid_entry == 0:
            print(f"Invalid {entity.table_entry}")
            return False, False

    # PATH TEST
    for respCov in resp.test_case.path_cov:
        for reqCov in req.test_case.path_cov:
            if reqCov.block_name == respCov.block_name:
                ''' found '''
                if reqCov.path_val != respCov.path_val:
                    print(f"Invalid path val in {reqCov.block_name}: {reqCov.path_val.hex()} vs. {respCov.path_val.hex()}")
                    return False, False
                if reqCov.path_size != respCov.path_size:
                    print(f"Invalid path size in {reqCov.block_name}: {respCov.path_size.hex()}")
                    return False, False
                break;


    return True, False


def p4testgen_get_coverage(stub, deviceId, options):
    req = p4testgen_pb2.P4CoverageRequest(
            device_id=deviceId)

    response = stub.GetP4Coverage(req)
    bitmap = response.test_case.stmt_cov_bitmap
    actionBitmap = response.test_case.action_cov_bitmap
    print("Get %s Coverage: %d/%d rules, %d/%d stmt (%s), and %d/%d action (%s)" %
            (deviceId, len(response.test_case.entities), response.test_case.table_size,
             getHitCount(bitmap), response.test_case.stmt_cov_size, getHexString(bitmap),
             getHitCount(actionBitmap), response.test_case.action_cov_size, getHexString(actionBitmap)))

    if options.printStmt:
        idx = 1
        for i in range(0, len(bitmap)):
            if bitmap[i] != 0:
                for b in range(7, -1, -1):
                    if (bitmap[i] >> b) & 1:
                        req_idx = idx + 7 - b
                        stmt = p4testgen_get_statement(stub, req_idx)
                        print(f"({req_idx}): {stmt}")

            idx += 8

def p4testgen_get_statement(stub, idx):
    req = p4testgen_pb2.P4StatementRequest(idx=idx)

    resp = stub.GetP4Statement(req)
    return resp.statement

def run(options):
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.

    if options.test:

        if not os.path.isdir(options.test):
            print(f"[Error] Test is not directory")
            parser.print_help()
            sys.exit(2)

        testFiles = []
        for (dirpath, dirnames, filenames) in walk(options.test):
            for filename in filenames:
                if filename.endswith(".proto"):
                    testFiles.append(filename)
            break

        open(options.passed, 'a').close()
        file1 = open(options.passed, "r")
        fileLines = file1.readlines()
        for fileLine in fileLines:
            skipFile = fileLine.split(' ')[0].strip()
            if skipFile in testFiles:
                testFiles.remove(skipFile)

        file1.close()

        file1 = open(options.passed, "a")

        for idx, testFile in enumerate(testFiles):
            with grpc.insecure_channel(f"{options.ip}:{options.curGrpcPort}") as channel:
                stub = p4testgen_pb2_grpc.P4FuzzGuideStub(channel)
                print(f"-------------- RecordP4Coverage ({idx + 1}/{len(testFiles)}: {testFile}) --------------")
                isSuc, skipped = p4testgen_record_coverage_wo_dev(options, stub, options.test, testFile)
                if skipped or isSuc:
                    file1.write("%s%s\n" % (testFile, "" if not skipped else " (skipped)"))

                else:
                    print(f"{testFile} has failed")
                    break

        file1.close()


    elif not options.input:
        print(f"[Error] Cannot find input file")
        parser.print_help()
        sys.exit(2)

    elif not os.path.isfile(options.input):
        print(f"[Error] Cannot find input file")
        parser.print_help()
        sys.exit(2)

    else:
        with grpc.insecure_channel(f"{options.ip}:{options.curGrpcPort}") as channel:
            stub = p4testgen_pb2_grpc.P4FuzzGuideStub(channel)
            print("-------------- RecordP4Coverage --------------")
            p4testgen_record_coverage(stub, options.input, options.output)
            #print("-------------- GetP4Coverage --------------")
            #p4testgen_get_coverage(stub, "s1", options)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input",
            help="input sample proto file to send", metavar="FILE")
    parser.add_option("-r", "--repeat", dest="repeatCnt", default=1,
            help="set repeat count", type="int", metavar="CNT")
    parser.add_option("-t", "--test", dest="test",
            help="input proto directory to test", metavar="DIR")
    parser.add_option("-o", "--output", dest="output",
            help="output diff result", metavar="DIR")
    parser.add_option("-p", "--passed", dest="passed", default=".passed.txt",
            help="input txt file which has passed/skipped proto", metavar="DIR")
    parser.add_option("-x", "--ip", dest="ip", default="localhost",
            help="GRPC server IP address", metavar="IP")
    parser.add_option("--ignoreDiffCov", dest="ignoreDiffCov", default=False,
            help="specify whether to ignore coverage diff", action="store_true")
    parser.add_option("--printStmt", dest="printStmt", default=False,
            help="specify whether to ignore coverage diff", action="store_true")
    parser.add_option("--ignoreErr", dest="ignoreErr", default=False,
            help="specify whether to ignore error in P4CE", action="store_true")
    parser.add_option("-c", "--printCov", dest="printCov", default=-1,
            help="print all stmt coverage", type="int")
    parser.add_option("--removeInvalidRule", dest="removeInvalidRule", default=False, action="store_true")
    (options, args) = parser.parse_args()

    logging.basicConfig()
    i = 0
    failCnt = 0
    options.curGrpcPort = 50051

    if options.printCov >= 0:
        with grpc.insecure_channel(f"{options.ip}:{options.curGrpcPort}") as channel:
            stub = p4testgen_pb2_grpc.P4FuzzGuideStub(channel)
            for i in range(0, options.printCov):
                print(f"{i}: {p4testgen_get_statement(stub, i)}")
        sys.exit(2)

    prevTestCaseStr = None
    for i in range(0, options.repeatCnt):
        try:
            print(f"{i+1}/{options.repeatCnt}")
            run(options)
            if options.output is not None:
                with open(options.output, 'r') as f:
                    newTestCase = Parse(f.read(), p4testgen_pb2.TestCase())

                    newTestCaseStr = newTestCase.SerializeToString(deterministic=True)
                    if prevTestCaseStr is not None and \
                            prevTestCaseStr != newTestCaseStr:
                        print(f"diff!!!")
                        sys.exit(2)


            failCnt = 0
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                pass
            elif e.code() == grpc.StatusCode.UNIMPLEMENTED:
                pass

            else:
                print(f"[WARN] Failed in {i+1}th test for {options.curGrpcPort}")
                print(e)
                failCnt += 1
                if failCnt >= 3:
                    print(f"[ERROR] No available servers")
                    break
                if options.curGrpcPort == 50051:
                    options.curGrpcPort = 50052
                else:
                    options.curGrpcPort = 50051
