package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.protobuf.*;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.P4ToolConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.DeviceCodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionP4TestContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoDevice;
import edu.purdue.cs.pursec.ifuzzer.util.P4AgentDesc.AgentStatus;
import io.grpc.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz;
import p4.v1.P4RuntimeFuzz.*;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.FieldMatch.FieldMatchTypeCase;
import p4.v1.P4RuntimeFuzz.FieldMatch.LPM;
import p4.v1.P4RuntimeFuzz.TableAction.TypeCase;
import p4testgen.P4FuzzGuideGrpc;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class P4Util {
    private static Logger log = LoggerFactory.getLogger(P4Util.class);

    public static final int P4_NAME_TABLE = 0;
    public static final int P4_NAME_MATCH = 1;
    public static final int P4_NAME_ACTION = 2;
    public static final int P4_NAME_PARAM = 3;
    public static final int P4_NAME_MAX = 4;

    public static final int CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS = 1000;
    public static final int CONFIG_P4TOOL_P4CE_WAIT_TIMEOUT_MS = 5000;

    public static final int CONFIG_MIN_THRESHOLD_BMV2_BUG2_BYTE_LEN = 6;
    public static final int CONFIG_MAX_THRESHOLD_BMV2_BUG2_BYTE_LEN = 40;

    /**
     * P4 Coverage
     */
    private final String pipelineId;
    private int activeAgentIdx;
    private final List<P4AgentDesc> agentList;
    private final Map<Integer, P4AgentWaitThread> waitAgentMap;
    private ManagedChannel channel;
    private P4FuzzGuideGrpc.P4FuzzGuideBlockingStub blockingStub;
    private final List<Map<String, P4NameReply>> p4NameCache;

    public P4Util(String pipelineId, String p4ToolAgentAddr, int p4ToolAgentPort, int p4ToolAgentNum, String p4ToolPidPath) {
        this.pipelineId = pipelineId;
        this.activeAgentIdx = 0;
        this.agentList = new ArrayList<>();
        this.waitAgentMap = new HashMap<>();
        this.p4NameCache = new ArrayList<>();

        for (int i = 0; i < p4ToolAgentNum; i++) {
            P4AgentDesc agent;
            String pidPath = p4ToolPidPath + File.separatorChar + (i + 1);
            try {
                int agentPid = Integer.parseInt(Files.readAllLines(Paths.get(pidPath)).get(0));
                agent = new P4AgentDesc(p4ToolAgentAddr + ":" + (p4ToolAgentPort + i), agentPid);
            } catch (Exception ignore) {
                agent = new P4AgentDesc(p4ToolAgentAddr + ":" + (p4ToolAgentPort + i));
            }

            this.agentList.add(agent);
        }

        for (int i = 0; i < P4_NAME_MAX; i++) {
            p4NameCache.add(new HashMap<>());
        }
    }

    public enum P4VulnType {
        NONE,
        CTRL_LOOPBACK,
        CTRL_DISAPPEAR,
        HOST_LOOPBACK,
        HOST_TO_CTRL,
        HOST_TO_HOST,
        HOST_DISAPPEAR,
    }

    public enum P4KnownBugType {
        NONE,
        INT_RECIRC_LOOP,
    }

    public static boolean filterClass(String clazz) {
        if (clazz.contains("/intent/"))
            return true;

        // TODO: allow upf for fabric-upf
        if (clazz.contains("/upf/"))
            return true;

        return false;
    }

    public static boolean filterClassPath(String packageName) {
        if (!packageName.startsWith("/pipelines"))
            return false;

        switch (ConfigConstants.CONFIG_P4_PIPELINE) {
            case "org.stratumproject.fabric.bmv2":
            case "org.stratumproject.fabric-int.bmv2":
                // Skip basic
                if (packageName.startsWith("/pipelines/basic"))
                    return true;
            case "org.onosproject.pipelines.int":
            case "org.onosproject.pipelines.basic":
                // Invalidate default fabric for all pipelines
                if (packageName.startsWith("/pipelines/fabric"))
                    return true;
                break;

            default:
                // Don't filter out any class
                break;
        }
        return false;
    }

    public static String getPipelineClassPath() {
        if (!ConfigConstants.CONFIG_P4_PIPELINE.startsWith("org.stratumproject.fabric"))
            return null;

        return P4ToolConstants.getFabricTnaClassPath();
    }

    public static boolean isInteresting(String className) {
        if (className.contains("P4RuntimeFlowRuleProgrammable") ||
                className.contains("P4RuntimePacketProgrammable"))
            return true;

        if (className.contains("org/onosproject/net/flow/"))
            return true;

        if (className.contains("org/onlab/packet"))
            return true;

        switch (ConfigConstants.CONFIG_P4_PIPELINE) {
            case "org.stratumproject.fabric.bmv2":
            case "org.stratumproject.fabric-int.bmv2":
                // Allow fabric
                if (className.contains("org/stratumproject/fabric/tna")) {
                    return true;
                }
                break;
            case "org.onosproject.pipelines.int":
            case "org.onosproject.pipelines.basic":
                // Invalidate default fabric for all pipelines
                if (className.contains("pipelines/basic"))
                    return true;
                break;

            default:
                break;
        }
        return false;
    }

    private void killGrpc(int agentIdx) {
        int agentPid = agentList.get(agentIdx).getAgentPid();
        if (agentPid > 0) {
            try {
                /* Kill */
                log.info("Kill P4CE agent {}", agentIdx);
                Runtime run = Runtime.getRuntime();
                String command = "kill -SIGUSR1 " + agentPid;
                Process pr = run.exec(command);
                pr.waitFor();

            } catch (IOException | InterruptedException e) {
                log.warn("kill {}: {}", agentPid, e.getMessage());
            }
        }
    }

    private int getNextAgentIdx(int agentIdx) {
        agentIdx++;
        if (agentIdx == P4ToolConstants.getP4toolAgentNum())
            return 0;
        return agentIdx;
    }

    private boolean areAllInactive(boolean[] isInactive) {
        for (boolean b : isInactive) if (!b) return false;
        return true;
    }

    private boolean initGrpc(int trialNum) {
        P4AgentDesc curAgent = agentList.get(activeAgentIdx);
        if (blockingStub == null) {
            String targetAddr = curAgent.getAgentAddr();
            log.debug("Connect to grpc:{}", targetAddr);
            channel = Grpc.newChannelBuilder(targetAddr, InsecureChannelCredentials.create())
                    .build();
            blockingStub = P4FuzzGuideGrpc.newBlockingStub(channel);
        }

        int curActiveIdx = activeAgentIdx;
        for (int i = 0; i < trialNum; i++) {
            try {
                // Try to connect
                HealthCheckResponse resp = blockingStub
                        .withDeadlineAfter(CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS,
                                TimeUnit.MILLISECONDS)
                        .hello(HealthCheckRequest.newBuilder().build());
                if (resp != null && resp.getStatus() > 0) {
                    activeAgentIdx = curActiveIdx;
                    curAgent.setAgentStatus(AgentStatus.ACTIVE);
                    return true;
                }
            } catch (Exception e) {
                log.warn("grpc: " + e.getMessage());
            }

            closeGrpc();

            // kill p4testgen process by sending SIGUSR1 to agent
            killGrpc(curActiveIdx);

            /* Set TERMINATING */
            curAgent.setAgentStatus(AgentStatus.TERMINATING);
            P4AgentWaitThread waitAgentThread = new P4AgentWaitThread(curAgent);
            waitAgentMap.put(curActiveIdx, waitAgentThread);
            waitAgentThread.start();

            // Get next valid agent
            boolean[] isInactive = new boolean[P4ToolConstants.getP4toolAgentNum()];
            while (true) {
                curActiveIdx = getNextAgentIdx(curActiveIdx);

                // SUC 1) No wait thread
                if (!waitAgentMap.containsKey(curActiveIdx)) {
                    break;
                }

                // SUC 2) Not alive
                waitAgentThread = waitAgentMap.get(curActiveIdx);
                if (!waitAgentThread.isAlive()) {
                    // Remove thread
                    waitAgentMap.remove(curActiveIdx);
                    break;
                }

                // If waiting to grpc, check another agent
                if (!areAllInactive(isInactive)) {
                    isInactive[curActiveIdx] = true;

                } else {
                    // Otherwise, wait for a while
                    log.error("All agents are down!!!");
                    try {
                        synchronized (waitAgentThread) {
                            waitAgentThread.wait(CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS);
                        }
                    } catch (InterruptedException e) {
                        log.warn("wait P4AgentThread: " + e.getMessage());
                    }

                    if (!waitAgentThread.isAlive()) {
                        // Remove thread
                        waitAgentMap.remove(curActiveIdx);
                        break;
                    }
                }
            }

            curAgent = agentList.get(curActiveIdx);
            curAgent.setAgentStatus(AgentStatus.INIT);
            String targetAddr = curAgent.getAgentAddr();
            log.debug("Connect to grpc:{}", targetAddr);
            channel = Grpc.newChannelBuilder(targetAddr, InsecureChannelCredentials.create())
                    .build();
            blockingStub = P4FuzzGuideGrpc.newBlockingStub(channel);
        }

        return false;
    }

    private void closeGrpc() {
        if (blockingStub != null) {
            blockingStub = null;
            // ManagedChannels use resources like threads and TCP connections. To prevent leaking these
            // resources the channel should be shut down when it will no longer be used. If it may be used
            // again leave it running.

            try {
                channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                log.warn("closeGrpc: " + e.getMessage());
            }
        }
    }

    public @Nullable P4CoverageReply getP4Coverage(String deviceId, TestCase testCase) {
        if (!initGrpc(P4ToolConstants.getP4toolAgentConnectTrialNum())) {
            log.warn("Cannot connect to P4Tool server");
            return null;
        }

        P4CoverageRequest req = P4CoverageRequest.newBuilder()
                .setDeviceId(deviceId)
                .setTestCase(testCase)
                .build();
        return blockingStub.withWaitForReady().getP4Coverage(req);
    }

    public enum P4UtilErrorType {
        NONE,
        SERVER_DOWN,
        UNSUPPORTED,
        INVALID,
    }

    public class P4CoverageReplyWithError {
        P4CoverageReply resp = null;
        P4UtilErrorType errorType = P4UtilErrorType.NONE;

        public P4CoverageReplyWithError(P4CoverageReply resp) {
            this.resp = resp;
        }

        public P4CoverageReplyWithError(P4UtilErrorType errorType) {
            this.errorType = errorType;
        }

        public P4CoverageReply getResp() {
            return resp;
        }

        public P4UtilErrorType getErrorType() {
            return errorType;
        }

        public boolean isError() {
            return !errorType.equals(P4UtilErrorType.NONE);
        }
    }

    public @Nonnull P4CoverageReplyWithError genRuleP4Testgen(String deviceId, TestCase testCase) {
        return genRuleP4Testgen(deviceId, testCase, P4ToolConstants.getP4toolAgentConnectTrialNum());
    }

    public @Nonnull P4CoverageReplyWithError genRuleP4Testgen(String deviceId, TestCase testCase,
                                                             int trialNum) {
        /*
        TestCase.Builder newTestCaseBuilder = TestCase.newBuilder(testCase);
        for (int i = 0; i < testCase.getEntitiesCount(); i++) {
            Entity_Fuzz entity = testCase.getEntities(i);
            if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                continue;

            TableEntry newEntry = TableEntry.newBuilder(entity.getTableEntry())
                    .clearMatch()
                    .build();
            Entity_Fuzz newEntity = Entity_Fuzz.newBuilder(entity)
                    .setTableEntry(newEntry)
                    .build();
            newTestCaseBuilder.setEntities(i, newEntity);
        }
         */

        P4CoverageRequest req = P4CoverageRequest.newBuilder()
                .setDeviceId(deviceId)
                .setTestCase(testCase)
                .build();

        for (int i = 0; i < trialNum; i++) {
            // XXX: trialNum x trialNum
            if (!initGrpc(trialNum)) {
                log.warn("Cannot connect to P4Tool server");
                return new P4CoverageReplyWithError(P4UtilErrorType.SERVER_DOWN);
            }

            try {
                /*
                 * XXX: Be careful in setting timeout, since
                 * P4Tool allows only one client connection.
                 */
                P4CoverageReply resp = blockingStub.withWaitForReady()
                        .withDeadlineAfter(CONFIG_P4TOOL_P4CE_WAIT_TIMEOUT_MS,
                                TimeUnit.MILLISECONDS)
                        .genRuleP4Testgen(req);

                return new P4CoverageReplyWithError(resp);

            } catch (StatusRuntimeException e) {
                if (e.getStatus().equals(Status.CANCELLED) ||
                        e.getStatus().equals(Status.DEADLINE_EXCEEDED)) {
                    // KILL GRPC
                    log.warn("Terminate P4Tool server: {}", activeAgentIdx);
                    closeGrpc();
                    killGrpc(activeAgentIdx);
                    activeAgentIdx = getNextAgentIdx(activeAgentIdx);
                } else {
                    return new P4CoverageReplyWithError(P4UtilErrorType.UNSUPPORTED);
                }
            }
        }

        return new P4CoverageReplyWithError(P4UtilErrorType.INVALID);
    }

    public @Nonnull P4CoverageReplyWithError recordP4Testgen(String deviceId, TestCase testCase) {
        return recordP4Testgen(deviceId, testCase, P4ToolConstants.getP4toolAgentConnectTrialNum());
    }

    public @Nonnull P4CoverageReplyWithError recordP4Testgen(String deviceId, TestCase testCase,
                                                             int trialNum) {

        P4CoverageRequest req = P4CoverageRequest.newBuilder()
                .setDeviceId(deviceId)
                .setTestCase(testCase)
                .build();

        for (int i = 0; i < trialNum; i++) {
            // XXX: trialNum x trialNum
            if (!initGrpc(trialNum)) {
                log.warn("Cannot connect to P4Tool server");
                return new P4CoverageReplyWithError(P4UtilErrorType.SERVER_DOWN);
            }

            try {
                /*
                 * XXX: Be careful in setting timeout, since
                 * P4Tool allows only one client connection.
                 */
                P4CoverageReply resp = blockingStub.withWaitForReady()
                        .withDeadlineAfter(CONFIG_P4TOOL_P4CE_WAIT_TIMEOUT_MS,
                                TimeUnit.MILLISECONDS)
                        .recordP4Testgen(req);

                return new P4CoverageReplyWithError(resp);

            } catch (StatusRuntimeException e) {
                if (e.getStatus().equals(Status.CANCELLED) ||
                        e.getStatus().equals(Status.DEADLINE_EXCEEDED)) {
                    // KILL GRPC
                    log.warn("Terminate P4Tool server: {}", activeAgentIdx);
                    closeGrpc();
                    killGrpc(activeAgentIdx);
                    activeAgentIdx = getNextAgentIdx(activeAgentIdx);
                } else {
                    return new P4CoverageReplyWithError(P4UtilErrorType.UNSUPPORTED);
                }
            }
        }

        return new P4CoverageReplyWithError(P4UtilErrorType.INVALID);
    }


    public @Nullable P4NameReply getP4Name(int type, String target) {
        // use cache to reduce latency
        if (p4NameCache.get(type).containsKey(target)) {
            return p4NameCache.get(type).get(target);
        }

        // TODO: support multiple P4 programs and agents
        P4NameRequest.Builder reqBuilder = P4NameRequest.newBuilder()
                .setEntityType(type);
        if (target != null && !target.isEmpty()) {
            reqBuilder.setTarget(target);
        }
        P4NameRequest req = reqBuilder.build();

        while (true) {
            if (!initGrpc(P4ToolConstants.getP4toolAgentConnectTrialNum())) {
                log.warn("Cannot connect to P4Tool server");
                return null;
            }

            try {
                log.debug("getP4Name:{} on {}", getNameTypeStr(type), target);
                P4NameReply resp = blockingStub.withWaitForReady()
                        .withDeadlineAfter(CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS,
                                TimeUnit.MILLISECONDS)
                        .getP4Name(req);

                if (resp != null) {
                    p4NameCache.get(type).put(target, resp);
                    return resp;
                }

            } catch (StatusRuntimeException e) {
                log.warn(e.getMessage());
                return null;
            }
        }
    }

    /**
     * Static Methods
     */
    public static P4Testgen.TestCase getTestfromProto(String protoStr) throws ParseException {
        return TextFormat.parse(protoStr, P4Testgen.TestCase.class);
    }

    public static P4Testgen.TestCase getTestfromFile(String filePath) throws IOException {
        String protoStr = new String(Files.readAllBytes(Paths.get(filePath)));
        return TextFormat.parse(protoStr, P4Testgen.TestCase.class);
    }

    public static List<Entity_Fuzz> getEntitiesfromProto(String protoStr)
            throws ParseException {
        P4Testgen.TestCase testCase = TextFormat.parse(protoStr, P4Testgen.TestCase.class);
        return testCase.getEntitiesList();
    }

    public static List<Entity_Fuzz> getEntities(List<Entity_Fuzz> curList, boolean isValid) {
        return getEntities(curList, Optional.of(isValid), Optional.empty());
    }

    public static List<Entity_Fuzz> getEntities(List<Entity_Fuzz> curList, boolean isValid, boolean isMutant) {
        return getEntities(curList, Optional.of(isValid), Optional.of(isMutant));
    }

    public static List<Entity_Fuzz> getEntities(List<Entity_Fuzz> curList,
                                                Optional<Boolean> validity,
                                                Optional<Boolean> mutant) {
        if (curList.isEmpty())
            return List.of();

        // Collect valid entities including default rule
        return curList.stream()
                .filter(e -> e.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                .filter(e -> (validity
                        .map(b -> (((e.getTableEntry().getIsValidEntry() & 1) > 0) == b))
                        .orElse(true)))   // validity check
                .filter(e -> (mutant
                        .map(b -> (((e.getIsDefaultEntry() & 1) == 0) == b))
                        .orElse(true)))   // mutant check
                .collect(Collectors.toList());
    }

    public static String getVulnTypeStr(P4VulnType type) {
        switch (type) {
            case CTRL_LOOPBACK:
                return "CTRL_LOOPBACK";
            case CTRL_DISAPPEAR:
                return "CTRL_DISAPPEAR";
            case HOST_LOOPBACK:
                return "HOST_LOOPBACK";
            case HOST_TO_HOST:
                return "HOST_TO_HOST";
            case HOST_TO_CTRL:
                return "HOST_TO_CTRL";
            case HOST_DISAPPEAR:
                return "HOST_DISAPPEAR";
            default:
                return "NONE";
        }
    }

    public static String getNameTypeStr(int type) {
        switch (type) {
            case P4_NAME_TABLE:
                return "TABLE";
            case P4_NAME_MATCH:
                return "MATCH";
            case P4_NAME_ACTION:
                return "ACTION";
            case P4_NAME_PARAM:
                return "PARAM";
        }
        return "UNKNOWN";
    }

    private static boolean checkTTF_ONOS_BUG_DIRECT_ACTION(Entity_Fuzz entity) {
        if (entity.getOnosFlowStatus().equals("ADDED"))
            return false;

        assert(entity.getEntityCase().equals(EntityCase.TABLE_ENTRY));
        TableEntry entry = entity.getTableEntry();

        // Ignore if it's invalid entry
        if ((entry.getIsValidEntry() & 1) == 0)
            return false;

        // Ignore rule without action
        if (!entry.hasAction())
            return false;

        TableAction tableAction = entry.getAction();
        if (tableAction.getTypeCase() == TypeCase.TYPE_NOT_SET)
            return false;

        // hard-coding..
        if (entry.getTableName().equals("ingress.wcmp_control.wcmp_table")) {
            if (tableAction.getTypeCase() != TypeCase.ACTION_PROFILE_ACTION_SET)
                return true;
        } else if (entry.getTableName().equals("FabricIngress.next.hashed")) {
            if (tableAction.getTypeCase() != TypeCase.ACTION_PROFILE_ACTION_SET)
                return true;
        }

        return tableAction.getTypeCase() != TypeCase.ACTION;
    }

    private static boolean checkTTF_ONOS_BUG_DEFAULT_ACTION(Entity_Fuzz entity) {
        if (entity.getOnosFlowStatus().equals("ADDED"))
            return false;

        assert(entity.getEntityCase().equals(EntityCase.TABLE_ENTRY));
        TableEntry entry = entity.getTableEntry();
        // Ignore if it's invalid entry
        if ((entry.getIsValidEntry() & 1) == 0)
            return false;

        if (!entry.hasAction())
            return true;

        TableAction tableAction = entry.getAction();
        switch (tableAction.getTypeCase()) {
            case TYPE_NOT_SET:
                // No action
                return true;

            case ACTION_PROFILE_ACTION_SET:
            {
                ActionProfileActionSet actionSet = tableAction.getActionProfileActionSet();
                // If no actionProfileAction, it is empty action
                return actionSet.getActionProfileActionsCount() == 0;
            }
        }
        return false;
    }

    private static boolean checkTTF_ONOS_BUG_RULE_CHECK_DELAY(Entity_Fuzz entity,
                                                              List<Entity_Fuzz> allEntities) {
        assert(entity.getEntityCase().equals(EntityCase.TABLE_ENTRY));
        TableEntry entry = entity.getTableEntry();
        // Skip invalid entry
        if ((entry.getIsValidEntry() & 1) == 0)
            return false;

        return entity.getDuration() == 0;
    }

    public static Set<ChimeraTTF> runtimeCheckTTFFromEntity(Entity_Fuzz entity,
                                                             List<Entity_Fuzz> allEntities) {
        Set<ChimeraTTF> foundTTFSet = new HashSet<>();
        if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
            return foundTTFSet;

        if (checkTTF_ONOS_BUG_DEFAULT_ACTION(entity))
            foundTTFSet.add(ChimeraTTF.ONOS_BUG_DEFAULT_ACTION);

        if (checkTTF_ONOS_BUG_DIRECT_ACTION(entity))
            foundTTFSet.add(ChimeraTTF.ONOS_BUG_DIRECT_ACTION);

        if (foundTTFSet.isEmpty()) {
            /*
             * NOTE: It is hard to catch this bug.
             *       1) Bug occurs with no identical rule but same values since it creates same flow ID.
             *       2) ONOS updates 2-3 seconds hard to differentiate false positives.
             *       3) Duration does not change.
             */
            if (checkTTF_ONOS_BUG_RULE_CHECK_DELAY(entity, allEntities))
                foundTTFSet.add(ChimeraTTF.ONOS_BUG_RULE_CHECK_DELAY);
        }

        return foundTTFSet;
    }

    public static Set<ChimeraTTF> runtimeCheckTTFFromEntities(List<Entity_Fuzz> errorEntities,
                                                              List<Entity_Fuzz> allEntities) {
        Set<ChimeraTTF> foundTTFSet = new HashSet<>();
        if (CommonUtil.isRuntimeConfigTTFMode()) {
            for (Entity_Fuzz entity : errorEntities) {
                foundTTFSet.addAll(runtimeCheckTTFFromEntity(entity, allEntities));
            }
        }
        return foundTTFSet;
    }

    public static Set<ChimeraTTF> checkTTF_BMV2_BUG_EXPAND_PACKET_HEADER(P4Testgen.TestCase testCase) {

        if (testCase.getExpectedOutputPacketCount() == 0)
            return Set.of();

        int inPort = testCase.getInputPacket().getPort();
        int outPort = testCase.getExpectedOutputPacket(0).getPort();
        int outPacketLen = testCase.getExpectedOutputPacket(0).getPacket().toByteArray().length;

        if (outPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
            return Set.of();

        Set<ChimeraTTF> foundTTFSet = new HashSet<>();
        // XXX: directly read log files
        String dpAgentLogFilePath = TestUtil.getTestAgentLogRoot() + File.separator +
                "dp-agent-h" + outPort + "1.log-ttf-expand";
        File dpAgentLogFile = new File(dpAgentLogFilePath);
        if (dpAgentLogFile.exists()) {
            dpAgentLogFile.delete();
            if (outPacketLen >= CONFIG_MIN_THRESHOLD_BMV2_BUG2_BYTE_LEN &&
                    outPacketLen < CONFIG_MAX_THRESHOLD_BMV2_BUG2_BYTE_LEN) {
                if (inPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
                    foundTTFSet.add(ChimeraTTF.BMV2_BUG_EXPAND_HEADER_BY_CONTROLLER);
                else
                    foundTTFSet.add(ChimeraTTF.BMV2_BUG_EXPAND_HEADER);
            }
        }

        dpAgentLogFilePath = TestUtil.getTestAgentLogRoot() + File.separator +
                "dp-agent-h" + outPort + "1.log-ttf-shrink";
        dpAgentLogFile = new File(dpAgentLogFilePath);
        if (dpAgentLogFile.exists()) {
            dpAgentLogFile.delete();
            if (outPacketLen >= CONFIG_MIN_THRESHOLD_BMV2_BUG2_BYTE_LEN &&
                    outPacketLen < CONFIG_MAX_THRESHOLD_BMV2_BUG2_BYTE_LEN) {
                if (inPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
                    foundTTFSet.add(ChimeraTTF.BMV2_BUG_SHRINK_HEADER_BY_CONTROLLER);
                else
                    foundTTFSet.add(ChimeraTTF.BMV2_BUG_SHRINK_HEADER);
            }
        }

        return foundTTFSet;
    }

    public static Set<ChimeraTTF> afterCheckTTFFromScenario(FuzzScenario scenario) {
        Set<ChimeraTTF> foundTTFSet = new HashSet<>();

        if (!CommonUtil.isRuntimeConfigTTFMode())
            return foundTTFSet;
        P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(scenario);
        if (testCase == null)
            return foundTTFSet;

        foundTTFSet.addAll(checkTTF_BMV2_BUG_EXPAND_PACKET_HEADER(testCase));

        return foundTTFSet;
    }

    public static boolean check_P4CE_FP_multiple_output(@Nonnull P4Testgen.TestCase testCase) {
        if (testCase.getExpectedOutputPacketCount() > 0)
            return false;

        boolean sendToCpu = false;
        for (Entity_Fuzz entity : testCase.getEntitiesList()) {
            if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                continue;

            TableEntry entry = entity.getTableEntry();
            if ((entry.getIsValidEntry() & 1) == 0 || entry.getMatchedIdx() < 0)
                continue;

            TableAction tableAction = entry.getAction();
            Action action = null;
            switch (tableAction.getTypeCase()) {
                case ACTION:
                    action = tableAction.getAction();
                    break;

                case ACTION_PROFILE_ACTION_SET:
                    ActionProfileActionSet actionSet = tableAction.getActionProfileActionSet();
                    // If no actionProfileAction, it is empty action
                    if (actionSet.getActionProfileActionsCount() > 0) {
                        action = actionSet.getActionProfileActions(0).getAction();
                    }
                    break;
            }

            // skip default action, again
            if (action == null)
                continue;

            // If packet is supposed to be sent to cpu, it is FP
            if (!action.getActionName().equals("FabricIngress.acl.punt_to_cpu") &&
                    !action.getActionName().equals("FabricIngress.acl.copy_to_cpu"))
                continue;

            sendToCpu = true;
            break;
        }

        return sendToCpu;
    }

    public static boolean check_P4CE_FP_overwrite_action(@Nonnull P4Testgen.TestCase testCase) {
        Map<String, TableEntry> tableMatchedEntryMap = new HashMap<>();
        for (Entity_Fuzz entity : testCase.getEntitiesList()) {
            if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                continue;

            TableEntry entry = entity.getTableEntry();
            if ((entry.getIsValidEntry() & 1) == 0)
                continue;

            if (entry.getMatchedIdx() >= 0) {
                // Set matched entry in the table
                tableMatchedEntryMap.put(entry.getTableName(), entry);

            } else if (tableMatchedEntryMap.containsKey(entry.getTableName())) {
                TableEntry matchedEntry = tableMatchedEntryMap.get(entry.getTableName());
                // Don't care if two actions are same
                if (entry.getAction().equals(matchedEntry.getAction()))
                    continue;

                // Check matches
                Map<String, P4RuntimeFuzz.FieldMatch> matches1 = new HashMap<>();
                for (P4RuntimeFuzz.FieldMatch match : entry.getMatchList()) {
                    matches1.put(match.getFieldName(), match);
                }
                Map<String, P4RuntimeFuzz.FieldMatch> matches2 = new HashMap<>();
                for (P4RuntimeFuzz.FieldMatch match : matchedEntry.getMatchList()) {
                    matches2.put(match.getFieldName(), match);
                }

                if (matches1.keySet().size() != matches2.keySet().size())
                    continue;

                boolean hasSameMatches = true;
                for (String key : matches1.keySet()) {
                    if (!matches1.get(key).equals(matches2.get(key))) {
                        hasSameMatches = false;
                        break;
                    }
                }
                if (hasSameMatches)
                    return true;
            }
        }
        return false;
    }

    public static P4VulnType isVulnerable(P4Testgen.TestCase testCase) {
        // If no invariance check, skip P4 check
        if (!ConfigConstants.CONFIG_ENABLE_P4_INVARIANT_CHECK ||
                testCase.getExpectedOutputPacketCount() == 0)
            return P4VulnType.NONE;

        int inPort = testCase.getInputPacket().getPort();
        int outPort = testCase.getExpectedOutputPacket(0).getPort();

        if (inPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
            if (outPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
                return P4VulnType.CTRL_LOOPBACK;
            else if (outPort == 0)
                return P4VulnType.CTRL_DISAPPEAR;

        } else {

            boolean hasMatched = false;
            for (Entity_Fuzz entity : testCase.getEntitiesList()) {
                if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                    continue;

                TableEntry entry = entity.getTableEntry();
                if ((entry.getIsValidEntry() & 1) == 0 || entry.getMatchedIdx() < 0)
                    continue;

                hasMatched = true;
                break;
            }

            if (!hasMatched) {
                if (outPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
                    return P4VulnType.HOST_TO_CTRL;
                else if (inPort == outPort)
                    return P4VulnType.HOST_LOOPBACK;
                else if (outPort == 0)
                    return P4VulnType.HOST_DISAPPEAR;
                else
                    return P4VulnType.HOST_TO_HOST;
            }
        }

        return P4VulnType.NONE;
    }

    private static boolean check_FABRIC_BUG_INT_RECIRC(List<Entity_Fuzz> allEntities) {
        for (Entity_Fuzz entity : allEntities) {
            assert(entity.getEntityCase().equals(EntityCase.TABLE_ENTRY));
            TableEntry entry = entity.getTableEntry();

            // skip invalid or unmatched rule
            if (entry.getIsValidEntry() == 0 || entry.getMatchedIdx() < 0)
                continue;

            // skip default action
            if (!entry.hasAction())
                continue;

            TableAction tableAction = entry.getAction();
            Action action = null;
            switch (tableAction.getTypeCase()) {
                case ACTION:
                    action = tableAction.getAction();
                    break;

                case ACTION_PROFILE_ACTION_SET:
                    ActionProfileActionSet actionSet = tableAction.getActionProfileActionSet();
                    // If no actionProfileAction, it is empty action
                    if (actionSet.getActionProfileActionsCount() > 0) {
                        action = actionSet.getActionProfileActions(0).getAction();
                    }
                    break;
            }

            // skip default action, again
            if (action == null)
                continue;

            // 1) Entry has mark_to_report
            if (!action.getActionName().equals("FabricIngress.int_watchlist.mark_to_report"))
                continue;

            // 2) Entry has invalid IPv4
            boolean isIPValid = false;
            for (FieldMatch match : entry.getMatchList()) {
                if (match.getFieldName().equals("ipv4_valid")) {
                    boolean hasValue = false;
                    for (byte eb : match.getExact().getValue().toByteArray()) {
                        if (eb > 0) {
                            hasValue = true;
                            break;
                        }
                    }

                    isIPValid = hasValue;
                    break;
                }
            }

            if (!isIPValid)
                return true;
        }

        return false;
    }

    public static P4KnownBugType getP4KnownBugType(P4Testgen.TestCase testCase) {
        if (ConfigConstants.CONFIG_P4_PIPELINE.startsWith("org.stratumproject.fabric")) {
            // check
            if (check_FABRIC_BUG_INT_RECIRC(testCase.getEntitiesList()))
                return P4KnownBugType.INT_RECIRC_LOOP;
        }
        return P4KnownBugType.NONE;
    }

    private static boolean isKnownError(TableEntry wrongEntry) {
        // BUG4: P4Runtime API don't allow DC match
        int testMatchNum = wrongEntry.getMatchCount();

        for (FieldMatch match : wrongEntry.getMatchList()) {
            if (!match.getFieldMatchTypeCase().equals(FieldMatchTypeCase.LPM))
                continue;

            LPM lpm = match.getLpm();
            if (lpm.getPrefixLen() == 0)
                testMatchNum --;
        }

        return (testMatchNum == 0);
    }

    /*
     * Assume that all given entities are failed.
     */
    public static boolean isKnownError(List<Entity_Fuzz> entities) {
        if (entities.size() == 0)
            return false;

        /* If all failed entries are KNOWN, it is known error. */
        for (Entity_Fuzz entity : entities) {

            if (entity.getEntityCase() == EntityCase.TABLE_ENTRY) {
                TableEntry entry = entity.getTableEntry();
                boolean isValid = (entry.getIsValidEntry() & 1) > 0;
                // Invalid entry has been installed.
                if (!isValid)
                    return false;

                // Valid entry has unknown error
                if (!isKnownError(entry))
                    return false;

            } else {
                // Unknown type of entity
                return false;
            }
        }

        return true;
    }

    public static List<DeviceCodeCoverage> getTraceBits(boolean isReset) throws IOException {
        List<DeviceCodeCoverage> coverageList = new ArrayList<>();

        HttpURLConnection conn = TestUtil.requestDumpCov();
        if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300) {
            log.warn("[{}] Error in requesting dump coverage of devices",
                    conn.getResponseCode());
            return coverageList;
        }

        JsonObject resultJson = TestUtil.getJsonResultFromHttpConnection(conn);
        if (resultJson.has("cov")) {
            for (JsonElement covJsonElem : resultJson.get("cov").getAsJsonArray()) {
                JsonObject covJson = covJsonElem.getAsJsonObject();

                if (!covJson.has("id"))
                    continue;
                if (!covJson.has("filepath"))
                    continue;

                coverageList.add(new DeviceCodeCoverage(covJson.get("id").getAsString(),
                        Files.readAllBytes(Paths.get(covJson.get("filepath").getAsString()))));
            }

        } else if (resultJson.has("message")) {
            log.warn("[{}] Cannot get Tracebits: {}",
                    conn.getResponseCode(), resultJson.get("message").getAsString());
        } else {
            log.warn("[{}] Cannot get Tracebits", conn.getResponseCode());
        }

        if (isReset) {
            conn = TestUtil.requestClearCov();
            if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300) {
                log.warn("[{}] Error in requesting clear coverage of devices",
                        conn.getResponseCode());
            }
        }

        return coverageList;
    }

    public static DeviceCodeCoverage getTraceBits(TopoDevice device) throws IOException {
        HttpURLConnection conn = TestUtil.requestDumpCov(device.getId());

        JsonObject resultJson = TestUtil.getJsonResultFromHttpConnection(conn);
        String errorMsg = "Cannot get Tracebits of "
                + device.getId()
                + ": ["
                + conn.getResponseCode()
                + "]";

        if (!resultJson.has("cov")) {
            log.error("{} no cov field", errorMsg);
            return null;
        }

        for (JsonElement covJsonElem : resultJson.get("cov").getAsJsonArray()) {
            JsonObject covJson = covJsonElem.getAsJsonObject();

            if (!covJson.has("id"))
                continue;
            if (!covJson.has("filepath"))
                continue;

            if (covJson.has("message")) {
                log.error("{} {}", errorMsg, resultJson.get("message").getAsString());
                return null;
            }

            return new DeviceCodeCoverage(covJson.get("id").getAsString(),
                    Files.readAllBytes(Paths.get(covJson.get("filepath").getAsString())));
        }

        /* Unreachable ... */
        log.error(errorMsg);
        return null;
    }

    public static @Nullable FuzzAction getP4TestgenActionFromScenario(FuzzScenario scenario) {
        for (FuzzAction action : scenario.getActionList()) {
            // get p4test from the content
            if (!action.getActionCmd().equals("p4test"))
                continue;

            FuzzActionContent content = action.getContent();
            if (!(content instanceof FuzzActionP4TestContent))
                continue;

            return action;
        }

        return null;
    }

    public static @Nullable P4Testgen.TestCase getP4TestgenFromScenario(FuzzScenario scenario) {
        for (FuzzAction action : scenario.getActionList()) {
            // get p4test from the content
            if (!action.getActionCmd().equals("p4test"))
                continue;

            FuzzActionContent content = action.getContent();
            if (!(content instanceof FuzzActionP4TestContent))
                continue;

            return ((FuzzActionP4TestContent) content).getTestCase();
        }

        return null;
    }

    public static @Nullable String getP4TestgenIdFromScenario(FuzzScenario scenario) {
        for (FuzzAction action : scenario.getActionList()) {
            // get p4test from the content
            if (!action.getActionCmd().equals("p4test"))
                continue;

            FuzzActionContent content = action.getSeedContent();
            if (!(content instanceof FuzzActionP4TestContent))
                continue;

            return content.getId();
        }

        return null;
    }

    public static String genHashCode(List<Entity_Fuzz> entityList) {
        if (entityList == null || entityList.isEmpty())
            return "";

        List<HashCode> hashCodeList = entityList.stream()
                .filter(k -> k.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                .filter(k -> (k.getTableEntry().getIsValidEntry() & 1) > 0)
                .map(k -> TableEntry.newBuilder(k.getTableEntry())
                        .setMatchedIdx(-1)
                        .build())
                .map(k -> Hashing.sha1().hashString(k.toString(), StandardCharsets.UTF_8))
                .collect(Collectors.toList());
        if (hashCodeList.isEmpty())
            return "";

        return Hex.encodeHexString(Hashing.combineUnordered(hashCodeList).asBytes());
    }

    public static String genHashCodeFromMatched(List<Entity_Fuzz> entityList) {
        if (entityList == null || entityList.isEmpty())
            return "";

        List<HashCode> hashCodeList = entityList.stream()
                .filter(k -> k.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                .filter(k -> (k.getTableEntry().getIsValidEntry() & 1) > 0)
                .filter(k -> k.getTableEntry().getMatchedIdx() >= 0)
                .map(k -> TableEntry.newBuilder(k.getTableEntry()).build())
                .map(k -> Hashing.sha1().hashString(k.toString(), StandardCharsets.UTF_8))
                .collect(Collectors.toList());
        if (hashCodeList.isEmpty())
            return "";

        return Hex.encodeHexString(Hashing.combineUnordered(hashCodeList).asBytes());
    }

    public static int genPacketType(@Nonnull P4Testgen.TestCase testCase) {
        int packetTypeVal = 0;

        // I. IN_PORT (H-> 0-2 or C-> 3-5)
        if (testCase.getInputPacket().getPort() == ConfigConstants.CONFIG_P4_CONTROLLER_PORT)
            packetTypeVal += 3;

        // II. OUT_PORT (DROP 0 or PORT 1 or CTRL 2)
        if (testCase.getExpectedOutputPacketCount() > 0) {
            if (testCase.getExpectedOutputPacket(0).getPort() == ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
                packetTypeVal += 2;
            } else {
                packetTypeVal += 1;
            }
        }

        return packetTypeVal;
    }

    public static String getPacketTypeStr(int packetType) {
        switch (packetType) {
            case 0:
                return "H->X";
            case 1:
                return "H->H";
            case 2:
                return "H->C";
            case 3:
                return "C->X";
            case 4:
                return "C->H";
            case 5:
                return "C->C";
        }
        return "";
    }

    public static boolean hasControllerImpact(@Nonnull P4Testgen.TestCase testCase) {
        int packetType = P4Util.genPacketType(testCase);
        return (packetType >= 2);
    }

    public static FieldMatchTypeCase getMatchTypeCase(String type) {
        if (type.equalsIgnoreCase("exact")) {
            return FieldMatchTypeCase.EXACT;
        } else if (type.equalsIgnoreCase("lpm")) {
            return FieldMatchTypeCase.LPM;
        } else if (type.equalsIgnoreCase("ternary")) {
            return FieldMatchTypeCase.TERNARY;
        } else if (type.equalsIgnoreCase("range")) {
            return FieldMatchTypeCase.RANGE;
        } else if (type.equalsIgnoreCase("optional")) {
            return FieldMatchTypeCase.OPTIONAL;
        }

        return null;
    }

    /**
     * Singleton
     * TODO: multiple GRPC server connections for different P4 pipelines
     */
    private static class InnerP4Util {
        private static final P4Util instance = new P4Util(ConfigConstants.CONFIG_P4_PIPELINE,
                P4ToolConstants.getP4toolAgentAddr(),
                P4ToolConstants.getP4toolAgentPort(),
                P4ToolConstants.getP4toolAgentNum(),
                P4ToolConstants.getP4toolAgentPidPath());
    }

    public static P4Util getInstance() {
        return P4Util.InnerP4Util.instance;
    }
}
