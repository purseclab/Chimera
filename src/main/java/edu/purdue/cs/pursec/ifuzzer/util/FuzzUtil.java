package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.FastSourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.IntentJsonGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.NonTrackingGenerationStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.StreamBackedRandom;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.ZestIntentGuidance.Input;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.ZestIntentGuidance.LinearInput;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.ZestIntentGuidance.SeedInput;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.tools.ExecFileLoader;
import org.onlab.packet.EthType.EtherType;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.*;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.FieldMatch.*;
import p4.v1.P4RuntimeFuzz.FieldMatch.Optional;
import p4.v1.P4RuntimeFuzz.TableAction.TypeCase;
import p4testgen.P4Testgen.P4NameReply;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Objects.hash;

public class FuzzUtil {
    private static Logger log = LoggerFactory.getLogger(FuzzUtil.class);
    public static Generator<JsonObject> generator = new IntentJsonGenerator();
    private static final P4Util p4UtilInstance = P4Util.getInstance();

    public static final int P4_MAX_VALUE_BYTES = 16;      // 128 bits
    public static final int ONOS_MAX_PRIORITY = 65536;
    public static final int P4_MAX_PRIORITY = 40000;
    public static final int P4_MIN_PRIORITY = 1;

    public static CoverageUpdateInfo updateCoverages(@Nullable JavaCodeCoverage totalCtrlCov,
                                                     @Nullable JavaCodeCoverage localCtrlCov,
                                                     @Nonnull Map<String, DeviceCodeCoverage> totalDevCodeCovMap,
                                                     @Nonnull Map<String, DeviceCodeCoverage> localDevCodeCovMap,
                                                     @Nonnull Map<String, P4Coverage> totalDevP4StmtCovMap,
                                                     @Nonnull Map<String, P4Coverage> localDevP4StmtCovMap,
                                                     @Nonnull Map<String, P4Coverage> totalDevP4ActionCovMap,
                                                     @Nonnull Map<String, P4Coverage> localDevP4ActionCovMap,
                                                     @Nonnull Map<String, RuleTraceCoverage> totalRuleTraceCovMap,
                                                     @Nonnull Map<String, RuleTraceCoverage> localRuleTraceCovMap,
                                                     @Nonnull Map<String, RulePathCoverage> totalRulePathCovMap,
                                                     @Nonnull Map<String, RulePathCoverage> localRulePathCovMap) {

        CoverageUpdateInfo reason = new CoverageUpdateInfo();
        // append coverage data
        if (totalCtrlCov != null && totalCtrlCov.updateCoverage(localCtrlCov))
            reason.hasUpdated("CC", localCtrlCov);

        // append device coverage
        for (String localKey : localDevCodeCovMap.keySet()) {
            DeviceCodeCoverage localDevCodeCov = localDevCodeCovMap.get(localKey);
            String subKey = localKey.substring("device:".length());
            if (totalDevCodeCovMap.containsKey(localKey)) {
                if (totalDevCodeCovMap.get(localKey).updateCoverage(localDevCodeCov))
                    reason.hasUpdated("DC" + subKey, localDevCodeCov);
            } else {
                totalDevCodeCovMap.put(localKey, new DeviceCodeCoverage(localDevCodeCov));
                reason.hasUpdated("DC" + subKey, localDevCodeCov);
            }
        }

        // append device P4 coverage
        for (String localKey : localDevP4StmtCovMap.keySet()) {
            P4Coverage localDevP4Cov = localDevP4StmtCovMap.get(localKey);
            String subKey = localKey.substring("device:".length());
            if (totalDevP4StmtCovMap.containsKey(localKey)) {
                if (totalDevP4StmtCovMap.get(localKey).updateCoverage(localDevP4Cov))
                    reason.hasUpdated("PS" + subKey, localDevP4Cov);
            } else {
                totalDevP4StmtCovMap.put(localKey, new P4Coverage(localDevP4Cov));
                reason.hasUpdated("PS" + subKey, localDevP4Cov);
            }
        }

        // append device P4 coverage
        for (String localKey : localDevP4ActionCovMap.keySet()) {
            P4Coverage localDevP4Cov = localDevP4ActionCovMap.get(localKey);
            String subKey = localKey.substring("device:".length());
            if (totalDevP4ActionCovMap.containsKey(localKey)) {
                if (totalDevP4ActionCovMap.get(localKey).updateCoverage(localDevP4Cov))
                    reason.hasUpdated("PA" + subKey, localDevP4Cov);
            } else {
                totalDevP4ActionCovMap.put(localKey, new P4Coverage(localDevP4Cov));
                reason.hasUpdated("PA" + subKey, localDevP4Cov);
            }
        }

        // append rule-specific trace coverage
        for (String ruleKey : localRuleTraceCovMap.keySet()) {
            RuleTraceCoverage localRuleTraceCov = localRuleTraceCovMap.get(ruleKey);
            String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
            if (totalRuleTraceCovMap.containsKey(ruleKey)) {
                if (totalRuleTraceCovMap.get(ruleKey).updateCoverage(localRuleTraceCov))
                    reason.hasUpdated("RT" + subKey, localRuleTraceCov);
            } else {
                totalRuleTraceCovMap.put(ruleKey, new RuleTraceCoverage(localRuleTraceCov));
                reason.hasUpdated("RT" + subKey, localRuleTraceCov);
            }
        }

        // append rule-specific path coverage
        for (String ruleKey : localRulePathCovMap.keySet()) {
            RulePathCoverage localRulePathCov = localRulePathCovMap.get(ruleKey);
            String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
            if (totalRulePathCovMap.containsKey(ruleKey)) {
                if (totalRulePathCovMap.get(ruleKey).updateCoverage(localRulePathCov))
                    reason.hasUpdated("RP" + subKey, localRulePathCov);
            } else {
                totalRulePathCovMap.put(ruleKey, new RulePathCoverage(localRulePathCov));
                reason.hasUpdated("RP" + subKey, localRulePathCov);
            }
        }

        return reason;
    }

    public static CoverageUpdateInfo updateCoverages(@Nonnull FuzzScenario inputScenario,
                                                     @Nullable JavaCodeCoverage totalCtrlCov,
                                                     @Nonnull Map<String, DeviceCodeCoverage> totalDevCodeCovMap,
                                                     @Nonnull Map<String, P4Coverage> totalDevP4StmtCovMap,
                                                     @Nonnull Map<String, P4Coverage> totalDevP4ActionCovMap,
                                                     @Nonnull Map<String, RuleTraceCoverage> totalRuleTraceCovMap,
                                                     @Nonnull Map<String, RulePathCoverage> totalRulePathCovMap) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();
        // append coverage data
        if (totalCtrlCov != null && totalCtrlCov.updateCoverage(inputScenario.getCodeCoverage()))
            reason.hasUpdated("CC", inputScenario.getCodeCoverage());

        // append device coverage
        List<DeviceCodeCoverage> deviceCodeCoverages = inputScenario.getDeviceCodeCoverages();
        if (deviceCodeCoverages != null) {
            for (DeviceCodeCoverage deviceCodeCoverage : deviceCodeCoverages) {
                String deviceId = deviceCodeCoverage.getDeviceId();
                String subKey = deviceId.substring("device:".length());
                if (totalDevCodeCovMap.containsKey(deviceId)) {
                    if (totalDevCodeCovMap.get(deviceId).updateCoverage(deviceCodeCoverage))
                        reason.hasUpdated("DC" + subKey, deviceCodeCoverage);
                } else {
                    totalDevCodeCovMap.put(deviceId, new DeviceCodeCoverage(deviceCodeCoverage));
                    reason.hasUpdated("DC" + subKey, deviceCodeCoverage);
                }
            }
        }

        // append device P4 statement coverage
        List<P4Coverage> devP4StmtCoverages = inputScenario.getP4StatementCoverages();
        if (devP4StmtCoverages != null) {
            for (P4Coverage devP4StmtCoverage : devP4StmtCoverages) {
                String deviceId = devP4StmtCoverage.getDeviceId();
                String subKey = deviceId.substring("device:".length());
                if (totalDevP4StmtCovMap.containsKey(deviceId)) {
                    if (totalDevP4StmtCovMap.get(deviceId).updateCoverage(devP4StmtCoverage))
                        reason.hasUpdated("PS" + subKey, devP4StmtCoverage);
                } else {
                    totalDevP4StmtCovMap.put(deviceId, new P4Coverage(devP4StmtCoverage));
                    reason.hasUpdated("PS" + subKey, devP4StmtCoverage);
                }
            }
        }

        // append device P4 action coverage
        List<P4Coverage> devP4ActionCoverages = inputScenario.getP4ActionCoverages();
        if (devP4ActionCoverages != null) {
            for (P4Coverage devP4ActionCoverage : devP4ActionCoverages) {
                String deviceId = devP4ActionCoverage.getDeviceId();
                String subKey = deviceId.substring("device:".length());
                if (totalDevP4ActionCovMap.containsKey(deviceId)) {
                    if (totalDevP4ActionCovMap.get(deviceId).updateCoverage(devP4ActionCoverage))
                        reason.hasUpdated("PA" + subKey, devP4ActionCoverage);
                } else {
                    totalDevP4ActionCovMap.put(deviceId, new P4Coverage(devP4ActionCoverage));
                    reason.hasUpdated("PA" + subKey, devP4ActionCoverage);
                }
            }
        }

        // append rule-specific trace coverage
        List<RuleTraceCoverage> ruleTraceCoverages = inputScenario.getRuleTraceCoverages();
        if (ruleTraceCoverages != null) {
            for (RuleTraceCoverage ruleTraceCoverage : ruleTraceCoverages) {
                String ruleKey = ruleTraceCoverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
                if (totalRuleTraceCovMap.containsKey(ruleKey)) {
                    if (totalRuleTraceCovMap.get(ruleKey).updateCoverage(ruleTraceCoverage))
                        reason.hasUpdated("RT" + subKey, ruleTraceCoverage);
                } else {
                    totalRuleTraceCovMap.put(ruleKey, new RuleTraceCoverage(ruleTraceCoverage));
                    reason.hasUpdated("RT" + subKey, ruleTraceCoverage);
                }
            }
        }

        // append rule-specific path coverage
        List<RulePathCoverage> rulePathCoverages = inputScenario.getRulePathCoverages();
        if (rulePathCoverages != null) {
            for (RulePathCoverage rulePathCoverage : rulePathCoverages) {
                String ruleKey = rulePathCoverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
                if (totalRulePathCovMap.containsKey(ruleKey)) {
                    if (totalRulePathCovMap.get(ruleKey).updateCoverage(rulePathCoverage))
                        reason.hasUpdated("RP" + subKey, rulePathCoverage);
                } else {
                    totalRulePathCovMap.put(ruleKey, new RulePathCoverage(rulePathCoverage));
                    reason.hasUpdated("RP" + subKey, rulePathCoverage);
                }
            }
        }

        return reason;
    }


    public static JsonObject getIntentJsonFromGenerator(String input) throws IOException {
        SeedInput seedInput = new SeedInput(input);
        InputStream inputStream = createParameterStream(seedInput);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(File file) throws IOException {
        SeedInput seedInput = new SeedInput(file);
        InputStream inputStream = createParameterStream(seedInput);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(Input input) throws IOException {
        InputStream inputStream = createParameterStream(input);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(InputStream inputStream) {
        StreamBackedRandom randomFile = new StreamBackedRandom(inputStream, Long.BYTES);
        SourceOfRandomness sourceOfRandomness = new FastSourceOfRandomness(randomFile);
        GenerationStatus genStatus = new NonTrackingGenerationStatus(sourceOfRandomness);

        return generator.generate(sourceOfRandomness, genStatus);
    }

    public static InputStream createParameterStream(Input currentInput) {
        Random rand = new Random();
        // Return an input stream that reads bytes from a linear array
        return new InputStream() {
            int bytesRead = 0;

            @Override
            public int read() throws IOException {
                assert currentInput instanceof LinearInput : "ZestGuidance should only mutate LinearInput(s)";

                // For linear inputs, get with key = bytesRead (which is then incremented)
                LinearInput linearInput = (LinearInput) currentInput;
                // Attempt to get a value from the list, or else generate a random value
                int ret = linearInput.getOrGenerateFresh(bytesRead++, rand);
                // infoLog("read(%d) = %d", bytesRead, ret);
                return ret;
            }
        };
    }

    public static Input getZestInputFromIntentJson(String intentJsonStr) throws IOException {
        JsonObject intentJson = TestUtil.fromJson(intentJsonStr);

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            if (!((IntentJsonGenerator) generator).ejectIntentJson(intentJson, outputStream)) {
                throw new IOException("fail to eject intentJson to random string");
            }

            // convert to ByteArrayInputStream
            return new SeedInput(outputStream.toByteArray());
        }
    }

    public static Byte[] getCoverageBitmaps(ExecFileLoader loader, int mapSize) {
        Byte[] traceBits = new Byte[mapSize];

        traceBits[0] = 1;
        for (int i = 1; i < mapSize; i++)
            traceBits[i] = 0;

        for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
            int feedbackId = hash(data.getId()) % (mapSize - 1);
            if (feedbackId < 0)
                feedbackId += mapSize - 1;
            feedbackId += 1;

            for (boolean probe : data.getProbes()) {
                if (probe)
                    traceBits[feedbackId]++;
            }
        }
        return traceBits;
    }


    public static List<TopoOperation> getDiffTopoOperations(List<TopoOperation> prevList, List<TopoOperation> nextList) {
        List<TopoOperation> topoOperations = new ArrayList<>();

        log.debug("Get difference in topology operations between old({}) and new({})",
                prevList.size(), nextList.size());

        // Currently, curMatrix is applied in topology.
        int commonLen = 0;
        for (int i = 0; i < nextList.size(); i++) {

            if (i >= prevList.size())
                break;

            if (!nextList.get(i).typeEquals(prevList.get(i)))
                break;

            commonLen ++;
        }

        // 1) Revert applied operations of curMatrix
        if (commonLen < prevList.size()) {
            for (int i = prevList.size() - 1; i >= commonLen; i--) {
                topoOperations.add(prevList.get(i).invert());
            }
        }

        // 2) Add remaining operations of this matrix
        for (int i = commonLen; i < nextList.size(); i++) {
            topoOperations.add(nextList.get(i));
        }

        return topoOperations;
    }

    /**
     * random operations
     */
    public static JsonObject blackboxFuzzPoint(JsonObject pointJson, Random random) {
        if (pointJson.has("device")) {
            String deviceId = pointJson.get("device").getAsString();
            pointJson.addProperty("device", blackboxFuzzString(deviceId, random));
        }

        if (pointJson.has("port")) {
            String portId = pointJson.get("port").getAsString();
            boolean setPortNumber = random.nextBoolean();
            if (setPortNumber) {
                pointJson.addProperty("port", String.valueOf(randomPortNo(random)));
            } else {
                pointJson.addProperty("port", blackboxFuzzString(portId, random));
            }
        }

        return pointJson;
    }

    public static String blackboxFuzzString(String s, Random random) {
        int trials = 1;
        if (s.length() > 0)
            trials = random.nextInt(s.length()) + 1;

        for (int i = 0; i < trials; i++)
            s = mutateString(s, random);

        return s;
    }

    public static int generateP4ValidPort(Random random, boolean containsCtrl) {
        int maxPortNo = ConfigConstants.CONFIG_P4_MAX_ALLOW_PORT_NUM;
        // If allowing PACKET_OUT, increase one slot more
        if (containsCtrl)
            maxPortNo ++;
        int retPort = random.nextInt(maxPortNo);
        return (retPort == ConfigConstants.CONFIG_P4_MAX_ALLOW_PORT_NUM ?
                ConfigConstants.CONFIG_P4_CONTROLLER_PORT : retPort + 1);
    }

    public static byte[] generatePacketOut(int outPortNo, int byteLen, Random random) {
        // Randomly select output ports
        if (byteLen == 2) {
            /* add 7-bit padding on outPortNo */
            byte[] outPortBytes = new byte[2];
            outPortBytes[0] = (byte) (outPortNo >> 1);
            outPortBytes[1] = (byte) (outPortNo << 7);

            return outPortBytes;

        } else if (byteLen == 14) {
            boolean doForwarding = random.nextBoolean();
            byte[] outPortBytes = new byte[14];
            outPortBytes[0] = (byte) (outPortNo >> 8);
            outPortBytes[1] = (byte) (outPortNo);
            outPortBytes[3] = (byte) (doForwarding ? 1 : 0);
            outPortBytes[12] = (byte) 0xbf;
            outPortBytes[13] = (byte) 0x01;

            return outPortBytes;
        }

        return generateRandomBytes(byteLen, random);
    }

    public static byte[] fillPacketOut(byte[] curBytes, int outPortNo, int byteLen) {
        // Randomly select output ports
        if (byteLen == 2 && curBytes.length > 2) {
            /* add 7-bit padding on outPortNo */
            curBytes[0] = (byte) (outPortNo >> 1);
            curBytes[1] = (byte) (outPortNo << 7);
        } else if (byteLen == 14 && curBytes.length > 14) {
            curBytes[0] = (byte) (outPortNo >> 8);
            curBytes[1] = (byte) (outPortNo);
        }

        return curBytes;
    }

    public static int getPacketOutLen() {
        if (ConfigConstants.CONFIG_P4_PIPELINE.equals("org.onosproject.pipelines.basic") ||
                ConfigConstants.CONFIG_P4_PIPELINE.equals("org.onosproject.pipelines.int")) {
            return 2;
        } else if (ConfigConstants.CONFIG_P4_PIPELINE.startsWith("org.stratumproject.fabric")) {
            return 14;
        }
        return 0;
    }

    public static String mutateString(String s, Random random) {
        String newStr;

        if (s == null)
            s = "";

        int opr = random.nextInt(s.length() > 0 ? 3 : 1);
        switch (opr) {
            case 0:
                newStr = insertRandomChar(s, random);
                break;
            case 1:
                newStr = modifyRandomChar(s, random);
                break;
            case 2:
                newStr = deleteRandomChar(s, random);
                break;
            default:
                /* Unreachable... */
                newStr = s;
                break;
        }

        return newStr;
    }

    public static byte[] generateRandomBytes(int byteLen, Random random) {
        byte[] randBytes = new byte[byteLen];

        for (int i = 0; i < byteLen; i++)
            randBytes[i] = (byte) random.nextInt(0x100);

        return randBytes;
    }

    public static byte[] mutateBytes(byte[] bytes, int offset, Random random) {
        byte[] newBytes;
        int opr = random.nextInt(bytes.length > 0 ? 3 : 1);
        switch (opr) {
            case 0:
                newBytes = insertRandomByte(bytes, offset, random);
                break;
            case 1:
                newBytes = modifyRandomByte(bytes, offset, random);
                break;
            case 2:
                newBytes = deleteRandomByte(bytes, offset, random);
                break;
            default:
                /* Unreachable... */
                newBytes = bytes;
                break;
        }

        return newBytes;
    }

    public static byte[] updateBytes(byte[] curBytes, byte[] newBytes, byte[] maskBytes) {
        byte[] retBytes = new byte[Integer.max(newBytes.length, curBytes.length)];
        int i;
        for (i = 0; i < newBytes.length; i++) {
            int newByte = newBytes[i] & maskBytes[i];
            int curByte = i < curBytes.length ? curBytes[i] & (~maskBytes[i] & 0xff) : 0;
            retBytes[i] = (byte) (newByte | curByte);
        }

        for (; i < curBytes.length; i++) {
            retBytes[i] = curBytes[i];
        }
        return retBytes;
    }

    /**
     * random valid object operations
     */

    public static String randomValidHostId(Random random) {
        // [MAC] + [VLAN]
        String hostId = randomMacAddress(true, random);

        // ONOS neglects a middle character
        hostId += "/";

        hostId += randomVlanId(true, random);

        return hostId;
    }

    public static String randomValidHostId(SourceOfRandomness random) {
        // [MAC] + [VLAN]
        String hostId = randomMacAddress(true, random);

        // ONOS neglects a middle character
        hostId += "/";

        hostId += randomVlanId(true, random);

        return hostId;
    }

    public static void ejectHostId(String hostId, OutputStream outputStream) throws IOException {
        String macAddr = hostId.substring(0, "00:00:00:00:00:00".length());
        String vlanId = hostId.substring("00:00:00:00:00:00/".length());

        ejectMacAddress(macAddr, outputStream);
        ejectVlanIdForHost(vlanId, outputStream);
    }

    // TODO: support preferred port no in topology
    public static long randomPortNo(Random random) {
        long portNo;

        // Bound: [0, 0xffffff00]
        portNo = 0xffffffffL;
        while (portNo > 0xffffff00L) {
            portNo = random.nextLong() & 0xffffffffL;

            /* break, if port is reserved */
            if (portNo >= 0xfffffff8L)
                break;
        }

        return portNo;
    }

    public static long randomPortNo(SourceOfRandomness random) {
        long portNo;

        portNo = random.nextLong(0, 0xffffff00L + 8);
        if (portNo > 0xffffff00L) {
            portNo += 0xf7L;        /* ff8L ~ fffL */
        }

        return portNo;
    }

    public static void ejectPortNo(long portNo, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        long leftBytes = portNo >> Integer.SIZE;
        byteBuffer.putInt(0, (int)leftBytes);
        outputStream.write(byteBuffer.array());

        byteBuffer.putInt(0, (int)portNo);
        outputStream.write(byteBuffer.array());
    }

    public static String randomMacAddress(boolean isUnicast, Random random) {
        StringBuilder newStr = new StringBuilder();

        //[ ]:[ ]:[ ]:[ ]:[ ]:[ ]
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = randHexChar(random);

                if (isUnicast && i == 0 && j == 1) {
                    int base = Integer.parseInt(String.valueOf(hex), 16);
                    base &= 0xE;     // HEX & 1110
                    hex = Character.forDigit(base, 16);
                }

                newStr.append(hex);
            }
            if (i < 5)
                newStr.append(":");
        }

        return newStr.toString();
    }

    public static String randomMacAddress(boolean isUnicast, SourceOfRandomness random) {
        StringBuilder newStr = new StringBuilder();

        //[ ]:[ ]:[ ]:[ ]:[ ]:[ ]
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = randHexChar(random);

                if (isUnicast && i == 0 && j == 1) {
                    int base = Integer.parseInt(String.valueOf(hex), 16);
                    base &= 0xE;     // HEX & 1110
                    hex = Character.forDigit(base, 16);
                }

                newStr.append(hex);
            }
            if (i < 5)
                newStr.append(":");
        }

        return newStr.toString();
    }

    public static void ejectMacAddress(String macAddr, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = macAddr.charAt((i * 3) + j);
                int idx = randHexCharToIdx(hex);

                byteBuffer.putInt(0, idx);
                outputStream.write(byteBuffer.array());
            }
        }
    }

    private static char randHexCharFromIdx(int idx) {
        char chr = 'a';

        if (idx < 0 || idx > 21)
            return chr;

        switch(idx / 6) {
            case 0:
                // 0-5: a-f
                chr = (char)('a' + (idx % 6));
                break;
            case 1:
                // 6-11: A-F
                chr = (char)('A' + (idx % 6));
                break;
            default:
                // 12-21 (remainder): 0-9
                chr = (char)('0' + idx - 12);
                break;
        }

        return chr;
    }

    private static int randHexCharToIdx(char hex) throws IOException {
        if (hex >= 'a' && hex <= 'f')
            return hex - 'a';
        else if (hex >= 'A' && hex <= 'F')
            return hex - 'A' + 6;
        else if (hex >= '0' && hex <= '9')
            return hex - '0' + 12;

        throw new IOException(String.format("Wrong hex char: %c", hex));
    }

    public static char randHexChar(Random random) {
        int idx = random.nextInt(22);
        return randHexCharFromIdx(idx);
    }

    public static char randHexChar(SourceOfRandomness random) {
        int idx = random.nextInt(22);
        return randHexCharFromIdx(idx);
    }

    public static String randAlphabets(int length, boolean allowUpper, Random random) {
        String str = "";

        for (int i = 0; i < length; i++) {
            int idx = random.nextInt(allowUpper ? 52 : 26);
            switch (idx / 26) {
                case 0:
                    // 0-25: a-z
                    str += (char) ('a' + (idx % 26));
                    break;
                case 1:
                    // 26-51: A-Z
                    str += (char) ('A' + (idx % 26));
                    break;
                default:
                    // unreachable ...
                    break;
            }
        }

        return str;
    }

    public static short randomEthType(boolean favored, Random random) {
        if (favored) {
            EtherType[] supportedTypes = EtherType.values();
            // get random EtherType, except EtherType.UNKNOWN
            return supportedTypes[random.nextInt(supportedTypes.length - 1)].ethType().toShort();
        } else {
            return (short) random.nextInt(0x10000);
        }
    }

    public static short randomIpv4Proto(boolean favored, Random random) {
        byte[] knownIpv4Proto = new byte[] {1, 2, 6, 17, 103};
        if (favored) {
            return knownIpv4Proto[random.nextInt(knownIpv4Proto.length)];
        } else {
            return (short) random.nextInt(0x100);
        }
    }

    public static String randomVlanId(boolean isHostId, Random random) {
        int vlan;
        if (isHostId) {
            // vlan can be [-2, 4096]
            vlan = random.nextInt(4099) - 2;
        } else {
            // TODO: check range
            vlan = random.nextInt(4097);
        }

        if (vlan == -2)
            return "None";
        else if (vlan == -1)
            return "Any";
        else
            return String.valueOf(vlan);
    }

    public static String randomVlanId(boolean isHostId, SourceOfRandomness random) {
        int vlan;
        if (isHostId) {
            // vlan can be [-2, 4096]
            vlan = random.nextInt(4099) - 2;
        } else {
            // TODO: check range
            vlan = random.nextInt(4097);
        }

        if (vlan == -2)
            return "None";
        else if (vlan == -1)
            return "Any";
        else
            return String.valueOf(vlan);
    }

    public static void ejectVlanIdForHost(String vlanId, OutputStream outputStream) throws IOException {
        int vlan;

        if (vlanId.equals("None"))
            vlan = 0;
        else if (vlanId.equals("Any"))
            vlan = 1;
        else
            vlan = Integer.parseInt(vlanId) + 2;

        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        byteBuffer.putInt(vlan);
        outputStream.write(byteBuffer.array());
    }

    public static String randomIp(Random random) {
        StringBuilder ipStr = new StringBuilder();

        //[ ].[ ].[ ].[ ]
        for (int i = 0; i < 4; i++) {
            ipStr.append(random.nextInt(256));
            if (i < 3)
                ipStr.append(".");
        }

        return ipStr.toString();
    }

    public static String randomIp(String subnetStr, Random random) throws IllegalArgumentException {
        IPv4AddressWithMask subnet = IPv4AddressWithMask.of(subnetStr);
        return randomIp(subnet, random);
    }

    public static String randomIp(IPv4AddressWithMask subnet, Random random) {
        if (subnet.getMask().equals(IPv4Address.NO_MASK))
            return subnet.getValue().toString();
        IPv4Address subnetIp = subnet.getValue().and(subnet.getMask());
        int limit = subnet.getMask().not().getInt();
        int randRaw = random.nextInt(limit) + 1;

        return subnetIp.or(IPv4Address.of(randRaw)).toString();
    }

    public static String randomIpWithCidr(Random random) {
        while (true) {
            String ip = FuzzUtil.randomIp(random);
            int dstMask = random.nextInt(33);
            IPv4AddressWithMask subnet = IPv4AddressWithMask.of(String.format("%s/%d", ip, dstMask));
            IPv4Address subnetIp = subnet.getValue().and(subnet.getMask());
            if (!subnetIp.isUnspecified()) {
                return String.format("%s/%d", subnetIp.toString(), dstMask);
            }
        }
    }

    public static int randomTpPort(Random random) {
        return random.nextInt(0x10000);
    }

    public static String randomValidDpid(boolean isONOSValid, Random random) {
        // of:[16 length hex-integers]
        StringBuilder dpidStr = new StringBuilder("of:");

        for (int i = 0; i < 16; i++) {
            dpidStr.append(FuzzUtil.randHexChar(random));
        }

        if (isONOSValid)
            return dpidStr.toString().toLowerCase();

        return dpidStr.toString();
    }

    public static String randomValidDpid(boolean isONOSValid, SourceOfRandomness random) {
        // of:[16 length hex-integers]
        StringBuilder dpidStr = new StringBuilder("of:");

        for (int i = 0; i < 16; i++) {
            dpidStr.append(FuzzUtil.randHexChar(random));
        }

        if (isONOSValid)
            return dpidStr.toString().toLowerCase();

        return dpidStr.toString();
    }

    public static void ejectONOSDpid(String dpid, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < 16; i++) {
            char hex = dpid.charAt(i + 3);
            int idx = randHexCharToIdx(hex);

            byteBuffer.putInt(0, idx);
            outputStream.write(byteBuffer.array());
        }
    }

    /**
     * single-char operations
     */

    private static String genRandomChar(Random random) {
        return Character.toString((char)(32 + random.nextInt(95)));
    }

    public static String getRandomChars(int len, Random random) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(genRandomChar(random));
        }
        return sb.toString();
    }

    private static String insertRandomChar(String s, Random random) {
        String insChar = genRandomChar(random);

        if (s == null || s.length() == 0)
            return insChar;

        int insPos = random.nextInt(s.length());
        return s.substring(0, insPos) + insChar + s.substring(insPos);
    }

    public static byte[] insertRandomBytes(byte[] bytes, Random random, int finalLen) {
        byte[] newBytes = new byte[finalLen];

        int pos = 0, left = finalLen - bytes.length;
        for (int i = 0; i < finalLen; i++) {
            if (pos >= bytes.length) {
                newBytes[i] = (byte) random.nextInt(0x100);
                left --;
            } else if (left <= 0) {
                newBytes[i] = bytes[pos++];
            } else if (random.nextBoolean()) {
                newBytes[i] = (byte) random.nextInt(0x100);
                left --;
            } else {
                newBytes[i] = bytes[pos++];
            }
        }

        return newBytes;
    }

    public static byte[] insertBytes(byte[] bytes, byte[] newBytes, int pos) {
        if (newBytes.length == 0)
            return bytes;

        if (bytes == null || bytes.length == 0)
            return newBytes.clone();

        byte[] retBytes = new byte[bytes.length + newBytes.length];
        if (pos > 0)
            System.arraycopy(bytes, 0, retBytes, 0, pos);
        System.arraycopy(newBytes, 0, retBytes, pos, newBytes.length);
        if (pos < bytes.length)
            System.arraycopy(bytes, pos, retBytes, pos + newBytes.length, bytes.length - pos);

        return retBytes;
    }

    public static byte[] insertRandomByte(byte[] bytes, int offset, Random random) {
        byte randByte = (byte) random.nextInt(0x100);

        int insPos = random.nextInt(bytes.length + 1 - offset) + offset;

        log.debug("  + byte {} at {}/{}", String.format("%#02x", randByte),
                insPos, bytes.length);

        return insertBytes(bytes, new byte[] {randByte}, insPos);
    }

    private static String deleteRandomChar(String s, Random random) {
        if (s == null || s.length() == 0)
            return s;

        int delPos = random.nextInt(s.length());      // [0, len)
        if (delPos == 0)
            return s.substring(1);                  // [1, len)
        else if (delPos == s.length() - 1)
            return s.substring(0, delPos);      // [0, len - 1)

        return s.substring(0, delPos) + s.substring(delPos + 1);
    }

    public static byte[] deleteRandomByte(byte[] bytes, int offset, Random random) {
        if (bytes == null || bytes.length == 0)
            return bytes;

        int delPos = random.nextInt(bytes.length - offset) + offset;      // [0, len)
        log.debug("  - byte {} at {}/{}", String.format("%#02x", bytes[delPos]),
                delPos, bytes.length);

        if (delPos == 0)
            return Arrays.copyOfRange(bytes, 1, bytes.length);        // [1, len)
        else if (delPos == bytes.length - 1)
            return Arrays.copyOfRange(bytes, 0, delPos);      // [0, len - 1)

        byte[] newBytes = new byte[bytes.length - 1];
        System.arraycopy(bytes, 0, newBytes, 0, delPos);
        System.arraycopy(bytes, delPos + 1, newBytes, delPos, bytes.length - delPos - 1);
        return newBytes;
    }

    private static String modifyRandomChar(String s, Random random) {
        if (s == null || s.length() == 0)
            return s;

        String modChar = Character.toString((char)(32 + random.nextInt(95)));

        int modPos = random.nextInt(s.length());
        if (modPos == 0)
            return modChar + s.substring(1);                  // [1, len)
        else if (modPos == s.length() - 1)
            return s.substring(0, modPos - 1) + modChar;      // [0, len - 1)

        return s.substring(0, modPos - 1) + modChar + s.substring(modPos + 1);
    }

    public static byte[] modifyRandomByte(byte[] bytes, int offset, Random random) {
        if (bytes == null || bytes.length == 0)
            return bytes;

        byte randByte = (byte) random.nextInt(0x100);
        int modPos = random.nextInt(bytes.length - offset) + offset;      // [offset, len)
        log.debug("  +/- byte {}->{} at {}/{}", String.format("%#02x", bytes[modPos]),
                String.format("%#02x", randByte), modPos, bytes.length);
        bytes[modPos] = randByte;
        return bytes;
    }

    public static byte[] flipRandomByte(byte[] bytes, int offset, Random random) {
        if (bytes == null || bytes.length == 0)
            return bytes;

        int modPos = random.nextInt(bytes.length - offset) + offset;      // [offset, len)
        byte newByte = (byte)~bytes[modPos];
        log.debug("  flip byte {}->{} at {}/{}", String.format("%#02x", bytes[modPos]),
                String.format("%#02x", newByte), modPos, bytes.length);
        bytes[modPos] = newByte;
        return bytes;
    }

    public static byte[] dupSegment(byte[] bytes, int maxTotalLen, int maxSegLen, Random random) {
        if (bytes == null || bytes.length < 1)
            return bytes;

        int byteLen = bytes.length;
        int mutateLen = Integer.min(maxTotalLen - byteLen, maxSegLen);
        mutateLen = Integer.min(byteLen, mutateLen);
        mutateLen = random.nextInt(mutateLen) + 1;

        int prevPos = random.nextInt(byteLen - mutateLen + 1);
        int newPos = random.nextInt(byteLen - mutateLen + 1);
        if (prevPos < newPos && newPos < prevPos + mutateLen)
            newPos += mutateLen;

        log.debug("  duplicate bytes [{}:{}) -> {}", prevPos, prevPos + mutateLen, newPos);

        byte[] newBytes = new byte[byteLen + mutateLen];
        byte[] segBytes = Arrays.copyOfRange(bytes, prevPos, prevPos + mutateLen);
        if (newPos > 0)
            System.arraycopy(bytes, 0, newBytes, 0, newPos);
        System.arraycopy(segBytes, 0, newBytes, newPos, mutateLen);
        if (newPos < byteLen)
            System.arraycopy(bytes, newPos, newBytes, newPos + mutateLen, byteLen - newPos);
        return newBytes;
    }

    public static byte[] swapSegment(byte[] bytes, int maxSegLen, Random random) {
        if (bytes == null || bytes.length < 2)
            return bytes;

        int byteLen = bytes.length;
        int mutateLen = Integer.min(byteLen / 2, maxSegLen);
        mutateLen = random.nextInt(mutateLen) + 1;

        int prevPos = random.nextInt(byteLen - mutateLen + 1);

        int newPos;
        if (prevPos < mutateLen) {
            int randLen = byteLen - prevPos - mutateLen * 2 + 1;
            if (randLen <= 0)
                return bytes;
            newPos = random.nextInt(randLen) + prevPos + mutateLen;   // [prevPos + mutateLen, byteLen - mutateLen]
        } else if (prevPos > byteLen - mutateLen * 2) {
            newPos = random.nextInt(prevPos - mutateLen + 1);   // [0, prevPos - mutateLen]
        } else {
            // [0, prevPos - mutateLen] or [prevPos + mutateLen, byteLen - mutateLen]
            assert (byteLen >= mutateLen * 3);
            newPos = random.nextInt(byteLen - mutateLen * 3 + 1);
            if (newPos > prevPos - mutateLen)
                newPos += mutateLen * 2;
        }
        log.debug("  swap bytes [{}:{})<->[{}:{})", prevPos, prevPos + mutateLen,
                newPos, newPos + mutateLen);

        byte[] newBytes = new byte[byteLen];
        System.arraycopy(bytes, 0, newBytes, 0, byteLen);
        System.arraycopy(bytes, newPos, newBytes, prevPos, mutateLen);
        System.arraycopy(bytes, prevPos, newBytes, newPos, mutateLen);
        return newBytes;
    }

    public static byte[] truncateBytes(byte[] bytes, Random random) {
        if (bytes == null || bytes.length == 0)
            return bytes;

        int byteLen = bytes.length;
        int trunLen = random.nextInt(byteLen) + 1;
        int newLen = byteLen - trunLen;

        log.debug("  truncate {} bytes len:{}->{}", trunLen, byteLen, newLen);

        if (newLen == 0)
            return new byte[0];

        return Arrays.copyOfRange(bytes, 0, newLen);
    }


    public static byte[] expandBytes(byte[] bytes, int maxTotalLen, int maxSegLen, Random random) {
        int byteLen;
        if (bytes == null || bytes.length == 0)
            byteLen = 0;
        else
            byteLen = bytes.length;

        int mutateLen = Integer.min(maxTotalLen - byteLen, maxSegLen);
        int expandLen = random.nextInt(mutateLen) + 1;

        log.debug("  expand {} bytes len:{}->{}", expandLen, byteLen, byteLen + expandLen);

        byte[] newBytes = new byte[byteLen + expandLen];
        if (byteLen > 0)
            System.arraycopy(bytes, 0, newBytes, 0, byteLen);
        for (int i = 0; i < expandLen; i++) {
            newBytes[byteLen + i] = (byte) random.nextInt(0x100);
        }
        return newBytes;
    }

    /**
     * P4RuntimeFuzz operations
     * TBD: mutate length for given object
     */

    public static Exact randomExact(@Nullable Exact exact, int bitLen, Random random) {
        Exact.Builder newExactBuilder;
        byte[] newBytes;

        if (exact == null) {
            newExactBuilder = Exact.newBuilder();
            if (bitLen == 0 || (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean())) {
                newBytes = new byte[random.nextInt(P4_MAX_VALUE_BYTES)];
            } else {
                newBytes = new byte[bitLenToByteLen(bitLen)];
            }

        } else {
            newExactBuilder = Exact.newBuilder(exact);
            if (bitLen == 0)
                newBytes = exact.getValue().toByteArray();
            else
                newBytes = new byte[bitLenToByteLen(bitLen)];
        }

        random.nextBytes(newBytes);
        newExactBuilder.setValue(ByteString.copyFrom(newBytes));

        return newExactBuilder.build();
    }

    public static LPM randomLpm(@Nullable LPM lpm, int bitLen, Random random) {
        LPM.Builder newLpmBuilder;
        byte[] newBytes;
        int prefixLen;

        if (lpm == null) {
            newLpmBuilder = LPM.newBuilder();

            if (bitLen == 0 || (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean())) {
                newBytes = new byte[random.nextInt(P4_MAX_VALUE_BYTES)];
                prefixLen = random.nextInt(P4_MAX_VALUE_BYTES * 8 + 1);
            } else {
                newBytes = new byte[bitLenToByteLen(bitLen)];
                prefixLen = random.nextInt(bitLen + 1);
            }
            random.nextBytes(newBytes);

        } else {
            newLpmBuilder = LPM.newBuilder(lpm);
            if (bitLen == 0)
                newBytes = lpm.getValue().toByteArray();
            else
                newBytes = new byte[bitLenToByteLen(bitLen)];

            // Randomize either VALUE or PREFIX
            if (random.nextBoolean()) {
                random.nextBytes(newBytes);
                prefixLen = lpm.getPrefixLen();
            } else if (bitLen == 0) {
                prefixLen = random.nextInt(newBytes.length * 8 + 1);
            } else {
                prefixLen = random.nextInt(bitLen + 1);
            }
        }

        newLpmBuilder.setValue(ByteString.copyFrom(newBytes));
        newLpmBuilder.setPrefixLen(prefixLen);

        return newLpmBuilder.build();
    }

    public static Ternary randomTernary(@Nullable Ternary ternary, int bitLen, Random random) {
        Ternary.Builder newTernaryBuilder;
        byte[] valueBytes, maskBytes;
        int valueLen, maskLen;

        if (ternary == null) {
            newTernaryBuilder = Ternary.newBuilder();

            if (bitLen == 0 || (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean())) {
                valueLen = random.nextInt(P4_MAX_VALUE_BYTES);
            } else {
                valueLen = bitLenToByteLen(bitLen);
            }

            if (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean()) {
                maskLen = random.nextInt(P4_MAX_VALUE_BYTES);
            } else {
                maskLen = valueLen;
            }

            valueBytes = new byte[valueLen];
            maskBytes = new byte[maskLen];

            random.nextBytes(valueBytes);
            random.nextBytes(maskBytes);

        } else {
            newTernaryBuilder = Ternary.newBuilder(ternary);
            if (bitLen == 0) {
                valueBytes = ternary.getValue().toByteArray();
                maskBytes = ternary.getMask().toByteArray();
            } else {
                valueBytes = new byte[bitLenToByteLen(bitLen)];
                maskBytes = new byte[bitLenToByteLen(bitLen)];
            }

            // Randomize either VALUE or MASK
            if (random.nextBoolean()) {
                random.nextBytes(valueBytes);
            } else {
                random.nextBytes(maskBytes);
            }
        }

        newTernaryBuilder.setValue(ByteString.copyFrom(valueBytes));
        newTernaryBuilder.setMask(ByteString.copyFrom(maskBytes));

        return newTernaryBuilder.build();
    }

    public static Range randomRange(@Nullable Range range, int bitLen, Random random) {
        Range.Builder newRangeBuilder;
        byte[] lowBytes, highBytes;

        if (range == null) {
            int lowBitLen, highBitLen;
            newRangeBuilder = Range.newBuilder();

            if (bitLen == 0 || (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean())) {
                lowBitLen = random.nextInt(P4_MAX_VALUE_BYTES);
            } else {
                lowBitLen = bitLenToByteLen(bitLen);
            }

            if (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean()) {
                highBitLen = random.nextInt(P4_MAX_VALUE_BYTES);
            } else {
                highBitLen = lowBitLen;
            }

            lowBytes = new byte[lowBitLen];
            highBytes = new byte[highBitLen];

            random.nextBytes(lowBytes);
            random.nextBytes(highBytes);

            // Swap if low > high
            if (!ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX || random.nextBoolean()) {
                for (int i = 0; i < lowBytes.length && i < highBytes.length; i++) {
                    if (lowBytes[i] > highBytes[i]) {
                        // Reverse Order
                        byte[] tmpBytes = highBytes;
                        highBytes = lowBytes;
                        lowBytes = tmpBytes;
                        break;

                    } else if (lowBytes[i] < highBytes[i]) {
                        // Correct Order
                        break;
                    }
                }
            }

        } else {
            newRangeBuilder = Range.newBuilder(range);
            if (bitLen == 0) {
                lowBytes = range.getLow().toByteArray();
                highBytes = range.getHigh().toByteArray();
            } else {
                lowBytes = new byte[bitLenToByteLen(bitLen)];
                highBytes = new byte[bitLenToByteLen(bitLen)];
            }

            // Randomize one of values (i.e. low)
            random.nextBytes(lowBytes);

            // Swap if low > high
            if (!ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX || random.nextBoolean()) {
                for (int i = 0; i < lowBytes.length && i < highBytes.length; i++) {
                    if (lowBytes[i] > highBytes[i]) {
                        // Reverse Order
                        byte[] tmpBytes = highBytes;
                        highBytes = lowBytes;
                        lowBytes = tmpBytes;
                        break;

                    } else if (lowBytes[i] < highBytes[i]) {
                        // Correct Order
                        break;
                    }
                }
            }
        }

        newRangeBuilder.setLow(ByteString.copyFrom(lowBytes));
        newRangeBuilder.setHigh(ByteString.copyFrom(highBytes));

        return newRangeBuilder.build();
    }

    public static Optional randomOptional(@Nullable Optional optional, int bitLen, Random random) {
        Optional.Builder newOptionalBuilder;
        byte[] newBytes;

        if (optional == null) {
            newOptionalBuilder = Optional.newBuilder();
            if (bitLen == 0 || (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && random.nextBoolean())) {
                newBytes = new byte[random.nextInt(P4_MAX_VALUE_BYTES)];
            } else {
                newBytes = new byte[bitLenToByteLen(bitLen)];
            }

        } else {
            newOptionalBuilder = Optional.newBuilder(optional);
            if (bitLen == 0)
                newBytes = optional.getValue().toByteArray();
            else
                newBytes = new byte[bitLenToByteLen(bitLen)];
        }

        random.nextBytes(newBytes);
        newOptionalBuilder.setValue(ByteString.copyFrom(newBytes));

        return newOptionalBuilder.build();
    }

    public static int bitLenToByteLen(int bitLen) {
        return (bitLen == 0 ? 1 : (bitLen - 1) / 8 + 1);
    }
}
