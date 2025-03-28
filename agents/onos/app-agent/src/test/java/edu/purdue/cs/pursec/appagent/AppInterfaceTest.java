package edu.purdue.cs.pursec.appagent;

import com.google.protobuf.TextFormat.ParseException;
import com.google.protobuf.TextFormat;
import edu.purdue.cs.pursec.appagent.AppInterface.ControlPlaneRule;
import org.junit.Test;
import org.onosproject.net.Device;
import org.onosproject.net.NetTestTools;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.TableAction;
import p4.v1.P4RuntimeFuzz.TableEntry;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.OutputPacketAtPort;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;


public class AppInterfaceTest {

    public static final Device mockDevice = NetTestTools.device("a");
    @Test
    public void testPacketOut() {
        // 1. Get example protobuf msg
        String protoStr = null;
        try {
            protoStr = new String(Files.readAllBytes(Paths.get(
                    "src/test/resources/basic._23.proto")));
        } catch (IOException e) {
            System.out.print("[ERROR] fail to read protobuf file.\n");
            fail(e.toString());
        }

        try {
            P4Testgen.TestCase fileTestCase = TextFormat.parse(protoStr, P4Testgen.TestCase.class);

            byte[] rawPacket = fileTestCase.getInputPacket().getPacket().toByteArray();
            BigInteger metadataValue = new BigInteger(new byte[]{rawPacket[0], rawPacket[1]});
            // Get outputPort from [9-bit metadata][7-bit padding]
            BigInteger outputPort = metadataValue.shiftRight(7);
            ByteBuffer inputByte = ByteBuffer.wrap(Arrays.copyOfRange(rawPacket, 2, rawPacket.length));
            OutputPacketAtPort outputPacket = fileTestCase.getExpectedOutputPacketList().get(0);
            byte[] outRawPacket = outputPacket.getPacket().toByteArray();

            assertEquals(outputPort.longValue(), outputPacket.getPort());
            assertEquals(inputByte, ByteBuffer.wrap(outRawPacket));

        } catch (ParseException e) {
            System.out.print("[ERROR] fail to parse protobuf file.\n");
            fail(e.toString());
        }
    }

    @Test
    public void testParseFlow() {
        // 1. Get example protobuf msg
        String protoStr = null;
        try {
            protoStr = new String(Files.readAllBytes(Paths.get(
                    "src/test/resources/fabric_v1model._0.proto")));
        } catch (IOException e) {
            System.out.print("[ERROR] fail to read protobuf file.\n");
            fail(e.toString());
        }

        // 2. Parse file into obj with custom p4testgen.proto (Fuzzer)
        List<Entity_Fuzz> fileEntities = new ArrayList<>();
        try {
            P4Testgen.TestCase fileTestCase = TextFormat.parse(protoStr, P4Testgen.TestCase.class);
            fileEntities.addAll(fileTestCase.getEntitiesList());
        } catch (ParseException e) {
            System.out.print("[ERROR] fail to parse protobuf file.\n");
            fail(e.toString());
        }

        // 3. (1) Parse obj into msg (Fuzzer)
        P4Testgen.TestCase testCaseMsg = P4Testgen.TestCase.newBuilder()
                .addAllEntities(fileEntities)
                .build();

        String testCaseMsgStr = testCaseMsg.toString();
        // 3. (2) Parse msg(String) into msg(char[])
        char[] testCaseMsgData = Arrays.copyOf(testCaseMsgStr.toCharArray(),
                testCaseMsgStr.length());
//        testCaseMsgData[testCaseMsgStr.length()] = 0;

        // 4. Parse msg into obj (App)
        List<Entity_Fuzz> msgEntities = new ArrayList<>();
        P4Testgen.TestCase msgTestCase = null;
        try {
            msgTestCase = TextFormat.parse(new String(testCaseMsgData), P4Testgen.TestCase.class);
            msgEntities.addAll(msgTestCase.getEntitiesList());
        } catch (ParseException e) {
            System.out.print("[ERROR] fail to parse protobuf file.\n");
            fail(e.toString());
        }

        assertEquals(fileEntities.size(), msgEntities.size());
        System.out.printf("test case: %s\n", msgTestCase);

        // 5. Translate p4 entities into ONOS flow rules
//        List<FlowRule> flowRules = new ArrayList<>();

        for (Entity_Fuzz entity : msgEntities) {
            switch (entity.getEntityCase()) {
                case TABLE_ENTRY:
                    TableEntry tableEntry = entity.getTableEntry();
                    ControlPlaneRule controlPlaneRule = new ControlPlaneRule();
                    AppInterface.parseControlPlaneRule(entity,
                            mockDevice.id(), NetTestTools.APP_ID, controlPlaneRule);
                    System.out.printf("add flowRule! %s\n", controlPlaneRule.flowRule);
                    TableAction tableAction = tableEntry.getAction();
                    if (tableAction.getActionProfileActionSet().getActionProfileActionsCount() > 0) {
                        assertNotNull(controlPlaneRule.groupDesc);
                        System.out.printf("add group! %s\n", controlPlaneRule.groupDesc);
                    } else {
                        assertNull(controlPlaneRule.groupDesc);
                    }

//                    flowRules.add(flowRule);
                    break;
                default:
                    System.out.printf("Unsupported: %s\n", entity.getEntityCase());
                    break;
            }
        }
    }
}