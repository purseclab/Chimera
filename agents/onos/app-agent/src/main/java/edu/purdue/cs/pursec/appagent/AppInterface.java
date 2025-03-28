package edu.purdue.cs.pursec.appagent;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.TextFormat;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.appagent.codec.AppAgentCodec;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.group.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.runtime.*;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;
import p4.v1.P4RuntimeFuzz.*;
import p4.v1.P4RuntimeFuzz.FieldMatch.*;
import p4.v1.P4RuntimeFuzz.FieldMatch.Optional;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import java.io.*;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.slf4j.LoggerFactory.getLogger;

public class AppInterface extends Thread {
    private static final int CONFIG_P4_CONTROLLER_PORT = 255;
    private static final boolean CONFIG_REMOVE_ZERO_PREFIX = true;
    private static final Logger log = getLogger(AppInterface.class);
    private final AppAgent app;
    private final AppAgentCodec context;
    private Socket socket;
    private BufferedReader in;
    private PrintStream out;

    private static int groupIdOffset = 0;

    public static class ControlPlaneRule {
        FlowRule flowRule;
        GroupDescription groupDesc;

        public void setFlowRule(FlowRule flowRule) {
            this.flowRule = flowRule;
        }

        public void setGroup(GroupDescription groupDesc) {
            this.groupDesc = groupDesc;
        }
    }

    public AppInterface(AppAgent app) {
        this.app = app;
        this.context = new AppAgentCodec(app.codecService);
        context.registerService(IntentService.class, app.intentService);
        context.registerService(CoreService.class, app.coreService);
        context.registerService(FlowObjectiveService.class, app.flowObjectiveService);
        context.registerService(FlowRuleService.class, app.flowRuleService);
        context.registerService(GroupService.class, app.groupService);
        context.registerService(DeviceService.class, app.deviceService);
        context.registerService(HostService.class, app.hostService);
        context.registerService(PacketService.class, app.packetService);
        context.registerService(TopologyService.class, app.topologyService);
        context.registerService(PiPipeconfService.class, app.piPipeconfService);
    }

    private static GroupId getGroupId(DeviceId deviceId, TableEntry tableEntry) {
        int hashCode = deviceId.toString().hashCode() |
                tableEntry.getTableName().hashCode();

        TableAction tableAction = tableEntry.getAction();
        ActionProfileActionSet profileActionSet = tableAction.getActionProfileActionSet();

        List<Action> actionList = profileActionSet.getActionProfileActionsList().stream()
                .map(ActionProfileAction::getAction)
                .collect(Collectors.toList());

        for (Action action : actionList) {
            hashCode |= action.getActionName().hashCode();
        }

        return new GroupId(hashCode + groupIdOffset);
    }

    public static void parseGroup(TableEntry tableEntry, DeviceId deviceId, GroupId groupId,
                           ApplicationId appId, ControlPlaneRule controlPlaneRule) {
        TableAction tableAction = tableEntry.getAction();
        ActionProfileActionSet profileActionSet = tableAction.getActionProfileActionSet();
        if (profileActionSet.getActionProfileActionsCount() == 0)
            return;

        PiGroupKey groupKey = new PiGroupKey(PiTableId.of(tableEntry.getTableName()),
                PiActionProfileId.of(tableAction.getActionSelectorName()),
                groupId.id());

        List<Action> actionList = profileActionSet.getActionProfileActionsList().stream()
                .map(ActionProfileAction::getAction)
                .collect(Collectors.toList());

        List<GroupBucket> bucketList = new ArrayList<>();
        for (Action action : actionList) {
            PiAction.Builder piActionBuilder = PiAction.builder();
            for (Action.Param param : action.getParamsList()) {
                piActionBuilder.withParameter(new PiActionParam(
                        PiActionParamId.of(param.getParamName()),
                        ImmutableByteSequence.copyFrom(param.getValue().toByteArray())));
            }
            piActionBuilder.withId(PiActionId.of(action.getActionName()));

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .add(Instructions.piTableAction(piActionBuilder.build()))
                    .build();
            bucketList.add(DefaultGroupBucket.createSelectGroupBucket(treatment));
        }

        // Add new group
        controlPlaneRule.setGroup(new DefaultGroupDescription(deviceId,
                GroupDescription.Type.SELECT,
                new GroupBuckets(bucketList),
                groupKey,
                groupId.id(),
                appId));
    }


    public static void parseControlPlaneRule(Entity_Fuzz entity, DeviceId deviceId, ApplicationId appId,
                                             ControlPlaneRule controlPlaneRule)
            throws IllegalArgumentException {

        TableEntry tableEntry = entity.getTableEntry();
        final String tableId = tableEntry.getTableName();

        FlowRule.Builder frb = DefaultFlowRule.builder()
                .forTable(PiTableId.of(tableId))
                .withPriority(tableEntry.getPriority())
                .makePermanent();

        PiCriterion.Builder piMatchBuilder = PiCriterion.builder();
        for (FieldMatch match : tableEntry.getMatchList()) {
            PiMatchFieldId matchFieldId = PiMatchFieldId.of(match.getFieldName());
            switch (match.getFieldMatchTypeCase()) {
                case LPM:
                    LPM lpm = match.getLpm();
                    if (CONFIG_REMOVE_ZERO_PREFIX && lpm.getPrefixLen() == 0)
                        break;

                    piMatchBuilder.matchLpm(matchFieldId, lpm.getValue().toByteArray(),
                            lpm.getPrefixLen());
                    break;
                case EXACT:
                    Exact exact = match.getExact();
                    piMatchBuilder.matchExact(matchFieldId, exact.getValue().toByteArray());
                    break;
                case TERNARY:
                    Ternary ternary = match.getTernary();
                    byte[] maskBytes = ternary.getMask().toByteArray();
                    // Add match only if the mask is non-zero
                    if (!Arrays.equals(maskBytes, new byte[maskBytes.length])) {
                        piMatchBuilder.matchTernary(matchFieldId, ternary.getValue().toByteArray(),
                                ternary.getMask().toByteArray());
                    }
                    break;
                case RANGE:
                    Range range = match.getRange();
                    piMatchBuilder.matchRange(matchFieldId, range.getLow().toByteArray(),
                            range.getHigh().toByteArray());
                    break;
                case OPTIONAL:
                    Optional optional = match.getOptional();
                    piMatchBuilder.matchOptional(matchFieldId, optional.getValue().toByteArray());
                    break;
                default:
                    log.warn("Unsupported {} match", match.getFieldMatchTypeCase());
                    throw new IllegalArgumentException("Unsupported " + match.getFieldMatchTypeCase() + " match");
            }
        }

        frb.withSelector(DefaultTrafficSelector.builder()
                        .matchPi(piMatchBuilder.build()).build())
                .forDevice(deviceId)
                .fromApp(appId);

        if (tableEntry.hasAction()) {
            TableAction tableAction = tableEntry.getAction();

            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
            ActionProfileActionSet profileActionSet = tableAction.getActionProfileActionSet();
            boolean hasTreatment = true;
            switch (tableAction.getTypeCase()) {
                case ACTION: {
                    PiAction.Builder piActionBuilder = PiAction.builder();
                    Action action = tableAction.getAction();
                    for (Action.Param param : action.getParamsList()) {
                        piActionBuilder.withParameter(new PiActionParam(
                                PiActionParamId.of(param.getParamName()),
                                ImmutableByteSequence.copyFrom(param.getValue().toByteArray())));
                    }
                    piActionBuilder.withId(PiActionId.of(action.getActionName()));
                    treatmentBuilder.piTableAction(piActionBuilder.build());
                    break;
                }

                case ACTION_PROFILE_ACTION_SET: {
                    if (profileActionSet.getActionProfileActionsCount() > 0) {
                        // profile action may require indirect actions (e.g., Group)
                        // Calculate groupId = H(devId) | H(tableName) | H(actionName)
                        String groupIdValue = entity.getOnosGroupId();
                        GroupId groupId;
                        if (!groupIdValue.isEmpty())
                            groupId = new GroupId(Integer.parseInt(groupIdValue));
                        else
                            groupId = getGroupId(deviceId, tableEntry);

                        parseGroup(tableEntry, deviceId, groupId, appId, controlPlaneRule);
                        treatmentBuilder.piTableAction(PiActionProfileGroupId.of(groupId.id()));
                    }
                    break;
                }

                default:
                    hasTreatment = false;
                    break;
            }

            if (hasTreatment)
                frb.withTreatment(treatmentBuilder.build());
        }

        // Add new rule
        controlPlaneRule.setFlowRule(frb.build());
    }

    private Map<Entity_Fuzz, ControlPlaneRule> parseControlPlaneRules(DeviceId deviceId, String data)
            throws ParseException, IllegalArgumentException {
        P4Testgen.TestCase ruleTestCase = TextFormat.parse(data, P4Testgen.TestCase.class);
        List<Entity_Fuzz> entities = ruleTestCase.getEntitiesList();

        log.info("Send {} flow(s) to {}", entities.size(), deviceId.toString());
        Map<Entity_Fuzz, ControlPlaneRule> controlPlaneRulesMap = new HashMap<>();

        for (Entity_Fuzz entity : entities) {
            /* skip default entries */
            if ((entity.getIsDefaultEntry() & 1) == 1)
                continue;

            ControlPlaneRule entityRule = new ControlPlaneRule();
            switch (entity.getEntityCase()) {
                case TABLE_ENTRY:
                    parseControlPlaneRule(entity, deviceId, app.getAppId(), entityRule);
                    log.info("parse flowRule! {} ...", entityRule.flowRule);
                    if (entityRule.groupDesc != null)
                        log.info("+ parse group ({})", entityRule.groupDesc);
                    controlPlaneRulesMap.put(entity, entityRule);
                    break;
                default:
                    /* TODO */
                    log.warn("Unsupported {} entity", entity.getEntityCase());
                    break;
            }
        }

        return controlPlaneRulesMap;
    }

    private P4Testgen.TestCase internalGetRules(Map<Entity_Fuzz, ControlPlaneRule> controlPlaneRulesMap) {
        List<Entity_Fuzz> addedEntities = new ArrayList<>();
        for (Entity_Fuzz reqEntity : controlPlaneRulesMap.keySet()) {
            ControlPlaneRule controlPlaneRule = controlPlaneRulesMap.get(reqEntity);
            Entity_Fuzz.Builder entityBuilder = Entity_Fuzz.newBuilder(reqEntity);
            // 1) Set onosFlowId / onosFlowStatus
            FlowEntry flowEntry = app.flowRuleService.getFlowEntry(controlPlaneRule.flowRule);
            if (flowEntry != null) {
                entityBuilder.setOnosFlowId(flowEntry.id().toString())
                        .setOnosFlowStatus(flowEntry.state().toString())
                        .setDuration((int) flowEntry.life());
            } else {
                entityBuilder.setOnosFlowId(controlPlaneRule.flowRule.id().toString())
                        .setOnosFlowStatus("");
            }

            // 2) Set onosGroupId / onosGroupStatus
            GroupDescription groupDesc = controlPlaneRule.groupDesc;
            if (groupDesc != null) {
                Group group = app.groupService.getGroup(groupDesc.deviceId(),
                        groupDesc.appCookie());
                if (group != null) {
                    entityBuilder.setOnosGroupId(group.id().id().toString())
                            .setOnosGroupStatus(group.state().toString());
                } else {
                    entityBuilder.setOnosGroupId(groupDesc.givenGroupId().toString())
                            .setOnosGroupStatus("");
                }
            }

            addedEntities.add(entityBuilder.build());
        }

        return P4Testgen.TestCase.newBuilder().addAllEntities(addedEntities).build();
    }

    private P4Testgen.TestCase addRules(DeviceId deviceId, String data)
            throws ParseException, IllegalArgumentException {
        Map<Entity_Fuzz, ControlPlaneRule> controlPlaneRulesMap = parseControlPlaneRules(deviceId, data);

        if (controlPlaneRulesMap.size() > 0) {
            // 1) Add Groups First.
            controlPlaneRulesMap.values().stream()
                    .map(v -> v.groupDesc)
                    .filter(Objects::nonNull)
                    .forEach(g -> app.groupService.addGroup(g));

            // 2) Then, add FlowRules
            app.flowRuleService.applyFlowRules(controlPlaneRulesMap.values().stream()
                    .map(v -> v.flowRule)
                    .filter(Objects::nonNull)
                    .toArray(FlowRule[]::new));
        }

        return internalGetRules(controlPlaneRulesMap);
    }

    private void delRules(DeviceId deviceId, String data)
            throws ParseException, IllegalArgumentException {
        Map<Entity_Fuzz, ControlPlaneRule> controlPlaneRulesMap = parseControlPlaneRules(deviceId, data);

        if (controlPlaneRulesMap.size() > 0) {
            // 1) Delete Flows First.
            app.flowRuleService.removeFlowRules(controlPlaneRulesMap.values().stream()
                    .map(v -> v.flowRule)
                    .filter(Objects::nonNull)
                    .toArray(FlowRule[]::new));

            // 2) Then delete groups
            controlPlaneRulesMap.values().stream()
                    .map(v -> v.groupDesc)
                    .filter(Objects::nonNull)
                    .forEach(g -> app.groupService.removeGroup(deviceId, g.appCookie(), app.getAppId()));
        }
    }

    private P4Testgen.TestCase getRules(DeviceId deviceId, String data)
            throws ParseException, IllegalArgumentException {
        return internalGetRules(parseControlPlaneRules(deviceId, data));
    }

    private P4Testgen.TestCase modGroups(DeviceId deviceId, String data)
            throws ParseException, IllegalArgumentException {
        Map<Entity_Fuzz, ControlPlaneRule> controlPlaneRulesMap = parseControlPlaneRules(deviceId, data);
        boolean hasGroup = false;
        for (ControlPlaneRule controlPlaneRule : controlPlaneRulesMap.values()) {
            GroupDescription oldDesc = controlPlaneRule.groupDesc;
            if (oldDesc == null)
                continue;

            hasGroup = true;

            // (1) Apply new group first.
            GroupDescription newDesc = new DefaultGroupDescription(oldDesc.deviceId(),
                    oldDesc.type(),
                    oldDesc.buckets(),
                    oldDesc.appCookie(),
                    oldDesc.givenGroupId() + 1,
                    app.getAppId());
            app.groupService.addGroup(newDesc);

            // (2) Update flow treatment with new group
            FlowRule oldFlow = controlPlaneRule.flowRule;
            assert oldFlow != null;

            FlowRule newFlow = DefaultFlowRule.builder()
                    .forTable(oldFlow.table())
                    .withPriority(oldFlow.priority())
                    .makePermanent()
                    .withSelector(oldFlow.selector())
                    .withTreatment(DefaultTrafficTreatment.builder()
                            .piTableAction(PiActionProfileGroupId.of(newDesc.givenGroupId()))
                            .build())
                    .forDevice(deviceId)
                    .fromApp(app.getAppId())
                    .build();

            app.flowRuleService.applyFlowRules(newFlow);

            // (3) Update ControlPlaneRule
            controlPlaneRule.setFlowRule(newFlow);
            controlPlaneRule.setGroup(newDesc);
        }

        if (hasGroup) {
            groupIdOffset ++;
        }

        return internalGetRules(controlPlaneRulesMap);
    }

    private void emitPacketOut(DeviceId deviceId, PortNumber outPort, byte[] packet) {
        log.info("Packet out to {}:{} (len: {})", deviceId, outPort, packet.length);
        app.packetService.emit(new DefaultOutboundPacket(deviceId,
                DefaultTrafficTreatment.builder()
                        .setOutput(outPort).build(),
                ByteBuffer.wrap(packet)));
    }

    private String sendPacketOut(DeviceId deviceId, TestCase testCase)
            throws InvalidProtocolBufferException {
        PiPipeconf pipeconf = app.piPipeconfService.getPipeconf(deviceId).orElse(null);
        if (pipeconf == null)
            return null;
        P4Testgen.InputPacketAtPort packet = testCase.getInputPacket();
        byte[] rawPacket = packet.getPacket().toByteArray();

        if (pipeconf.id().toString().equals("org.onosproject.pipelines.basic") ||
                pipeconf.id().toString().equals("org.onosproject.pipelines.int")) {
            if (rawPacket.length <= 2) {
                return "Cannot send short packet (<= 2)";
            }
            BigInteger metadataValue = new BigInteger(new byte[]{rawPacket[0], rawPacket[1]});
            // Get outputPort from [9-bit metadata][7-bit padding]
            BigInteger outputPort = metadataValue.shiftRight(7).and(BigInteger.valueOf(0x1ff));

            emitPacketOut(deviceId,
                    PortNumber.portNumber(outputPort.longValue()),
                    Arrays.copyOfRange(rawPacket, 2, rawPacket.length));

        } else if (pipeconf.id().toString().startsWith("org.stratumproject.fabric")) {
            // XXX: get portNo from expected output, not from input packet.
            if (rawPacket.length <= 14) {
                return "Cannot send short packet (<= 14)";
            }

            // Anyway, check etherType
            if (!(rawPacket[12] == (byte)0xbf && rawPacket[13] == (byte)1)) {
                return String.format("unknown etherType: 0x%02X%02X", rawPacket[12], rawPacket[13]);
            }

            PortNumber outPort;
            if ((rawPacket[3] & 1) == 1) {
                outPort = PortNumber.TABLE;
            } else {
                BigInteger metadataValue = new BigInteger(new byte[]{rawPacket[0], rawPacket[1]});
                outPort = PortNumber.portNumber(metadataValue.and(BigInteger.valueOf(0x1ff)).longValue());
            }

            emitPacketOut(deviceId, outPort, Arrays.copyOfRange(rawPacket, 14, rawPacket.length));
        }
        return null;
    }

    private class RuleData {
        Device device;
        String data;
        String errorMsg = "";

        public RuleData(Device device, String data) {
            this.device = device;
            this.data = data;
        }

        public RuleData(String errorMsg) {
            this.errorMsg = errorMsg;
        }
    }

    private RuleData parseFromInterface(BufferedReader in) throws IOException {
        String line = in.readLine().trim();
        if (!line.startsWith("key:")) {
            return new RuleData(String.format("error:wrong request message %s", line));
        }

        String deviceId = line.substring("key:".length());

        line = in.readLine().trim();
        if (!line.startsWith("length:")) {
            return new RuleData(String.format("error:wrong request message %s", line));
        }

        // Get length
        int len = Integer.parseInt(line.substring("length:".length()));
        char[] data = new char[len];

        // Read intentStr
        log.info("Read {} length", len);
        int off = 0;
        while (off < len) {
            off += in.read(data, off, len - off);
        }
        String dataStr = new String(data);

        Device device = app.deviceService.getDevice(DeviceId.deviceId(deviceId));
        if (device == null) {
            return new RuleData(String.format("error:cannot find device %s", deviceId));
        }

        return new RuleData(device, dataStr);
    }

    @Override
    public void run() {
        while (true) {
            try {
                while (true) {
                    try {
                        socket = new Socket("127.0.0.1", 9000);
                        break;
                    } catch (ConnectException e) {
                        TimeUnit.MILLISECONDS.sleep(500);
                    }
                }

                log.info("Connect to server");

                out = new PrintStream(socket.getOutputStream());
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            } catch (Exception e) {
                log.error("Fail to connect server: " + e.getMessage());
            }

            try {
                try {
                    while (true) {
                        String command = in.readLine();
                        if (command == null)
                            break;

                        command = command.trim();
                        String actionId = null;
                        switch (command) {
                            case "CLEAR_PACKET":
                            {
                                String line = in.readLine().trim();
                                if (!line.startsWith("action:")) {
                                    out.printf("error:wrong request message %s%n", line);
                                    out.flush();
                                    continue;
                                }
                                actionId = line.substring("action:".length());
                                app.expectedPacketMultiMap.remove(actionId);
                                out.println("key:0");
                                break;
                            }

                            case "EXPECT_PACKET":
                            {
                                String line = in.readLine().trim();
                                if (!line.startsWith("action:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }
                                actionId = line.substring("action:".length());
                                RuleData ruleData = parseFromInterface(in);
                                if (!ruleData.errorMsg.isEmpty()) {
                                    out.println(ruleData.errorMsg);
                                    out.flush();
                                    continue;
                                }
                                try {
                                    P4Testgen.TestCase testCase = TextFormat.parse(ruleData.data, P4Testgen.TestCase.class);
                                    int inPort = testCase.getInputPacket().getPort();

                                    List<P4Testgen.OutputPacketAtPort> outputPacketBytes = new ArrayList<>();
                                    for (P4Testgen.OutputPacketAtPort outputPacket : testCase.getExpectedOutputPacketList()) {
                                        if (outputPacket.getPort() != CONFIG_P4_CONTROLLER_PORT)
                                            continue;

                                        outputPacketBytes.add(outputPacket);
                                    }
                                    Map<String, List<P4Testgen.OutputPacketAtPort>> expectedPacketMap = new HashMap<>();
                                    expectedPacketMap.put(ruleData.device.id().toString() + "/" + inPort, outputPacketBytes);
                                    app.expectedPacketMultiMap.put(actionId, expectedPacketMap);
                                    out.println("key:0");
                                } catch (ParseException e) {
                                    out.println("error:" + e.getMessage());
                                }

                                break;
                            }

                            case "SEND_PACKET":
                            {
                                String line = in.readLine().trim();
                                if (!line.startsWith("action:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }
                                actionId = line.substring("action:".length());
                                RuleData ruleData = parseFromInterface(in);
                                if (!ruleData.errorMsg.isEmpty()) {
                                    out.println(ruleData.errorMsg);
                                    out.flush();
                                    continue;
                                }
                                try {
                                    P4Testgen.TestCase testCase = TextFormat.parse(ruleData.data, P4Testgen.TestCase.class);
                                    P4Testgen.InputPacketAtPort inputPacketAtPort = testCase.getInputPacket();
                                    if (inputPacketAtPort.getPort() != CONFIG_P4_CONTROLLER_PORT) {
                                        out.println("error:wrong port");
                                        continue;
                                    }
                                    String errorMsg = sendPacketOut(ruleData.device.id(), testCase);
                                    if (errorMsg != null) {
                                        out.println("error:" + errorMsg);
                                    } else {
                                        out.println("key:0");
                                    }
                                } catch (Exception e) {
                                    out.println("error:" + e.getMessage());
                                }
                                break;
                            }

                            case "PACKET_OUT": {
                                String line = in.readLine().trim();
                                if (!line.startsWith("action:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }
                                actionId = line.substring("action:".length());
                                line = in.readLine().trim();
                                if (!line.startsWith("key:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }
                                String deviceId = line.substring("key:".length());
                                line = in.readLine().trim();
                                if (!line.startsWith("port:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }
                                String portStr = line.substring("port:".length());
                                line = in.readLine().trim();
                                if (!line.startsWith("length:")) {
                                    out.printf("error:wrong request message %s\n", line);
                                    out.flush();
                                    continue;
                                }

                                // Get length
                                int len = Integer.parseInt(line.substring("length:".length()));
                                char[] data = new char[len];

                                // Read intentStr
                                log.info("Read {} length", len);
                                int off = 0;
                                while (off < len) {
                                    off += in.read(data, off, len - off);
                                }
                                emitPacketOut(DeviceId.deviceId(deviceId), PortNumber.portNumber(portStr),
                                        Base64.getDecoder().decode(new String(data)));
                                out.println("key:0");
                                break;
                            }

                            case "ADDRULE":
                            case "DELRULE":
                            case "GETRULE":
                            case "MODGROUP": {
                                RuleData ruleData = parseFromInterface(in);
                                if (!ruleData.errorMsg.isEmpty()) {
                                    out.println(ruleData.errorMsg);
                                    out.flush();
                                    continue;
                                }

                                try {
                                    log.debug("Received: {}", ruleData.data);

                                    if (command.equals("ADDRULE")) {
                                        //ADDRULE
                                        P4Testgen.TestCase retTest = addRules(ruleData.device.id(), ruleData.data);
                                        String retData = retTest.toString();
                                        out.println("length:" + retData.length());
                                        out.print(retData);
                                        //out.write(retData.getBytes(), 0, retData.length());
                                        out.flush();

                                    } else if (command.equals("GETRULE")) {
                                        // GETRULE
                                        P4Testgen.TestCase retTest = getRules(ruleData.device.id(), ruleData.data);
                                        String retData = retTest.toString();
                                        out.println("length:" + retData.length());
                                        out.print(retData);
                                        //out.write(retData.getBytes(), 0, retData.length());
                                        out.flush();

                                    } else if (command.equals("MODGROUP")) {
                                        // MODGROUP
                                        P4Testgen.TestCase retTest = modGroups(ruleData.device.id(), ruleData.data);
                                        String retData = retTest.toString();
                                        out.println("length:" + retData.length());
                                        out.print(retData);
                                        //out.write(retData.getBytes(), 0, retData.length());
                                        out.flush();

                                    } else {
                                        // DELRULE
                                        delRules(ruleData.device.id(), ruleData.data);
                                        out.println("key:0");
                                    }

                                } catch (ParseException | IllegalArgumentException e) {
                                    out.println("error:" + e.getMessage());
                                }
                                break;
                            }
                            case "ADD": {
                                String line = in.readLine().trim();
                                if (line.startsWith("length:")) {
                                    // Get length
                                    int len = Integer.parseInt(line.substring("length:".length()));
                                    char[] data = new char[len + 1];

                                    // Read intentStr
                                    log.info("Read {} length", len);
                                    int readLen = in.read(data, 0, len);
                                    data[readLen] = 0;
                                    String dataStr = new String(data);

                                    try {
                                        log.info("Parse data: {} ({} length)", dataStr, readLen);
                                        ObjectNode root = (ObjectNode) context.mapper().readTree(dataStr);

                                        log.info("Decode Json into intent: {}", root.toString());
                                        Intent intent = context.codec(Intent.class).decode(root, context);

                                        log.info("Submit intent to service");
                                        app.intentService.submit(intent);

                                        log.info("Send intent key: {}", intent.key().toString());
                                        out.println("key:" + intent.key());
                                    } catch (Exception e) {
                                        out.println("error:unsupported intent: " + e.getMessage());
                                    }

                                } else {
                                    out.printf("error:wrong request message %s%n", line);
                                }

                                break;
                            }
                            case "MODIFY": {
                                String line = in.readLine().trim();

                                // Get AppId
                                if (!line.startsWith("appId:")) {
                                    out.printf("error:wrong request message %s%n", line);
                                    out.flush();
                                    continue;
                                }
                                String appIdStr = line.substring("appId:".length());
                                final ApplicationId appId = app.coreService.getAppId(appIdStr);
                                if (appId == null) {
                                    out.printf("error:wrong appId %s%n", appIdStr);
                                    out.flush();
                                    continue;
                                }

                                // Get Key
                                line = in.readLine().trim();
                                if (!line.startsWith("key:")) {
                                    out.printf("error:wrong request message %s%n", line);
                                    out.flush();
                                    continue;
                                }
                                String keyStr = line.substring("key:".length());

                                // Get final key from keyStr and appId
                                Key key = Key.of(Long.decode(keyStr), appId);
                                log.info("{} intent appId:{}, key:{}", command, appIdStr, keyStr);

                                line = in.readLine().trim();
                                if (line.startsWith("length:")) {
                                    // Get length
                                    int len = Integer.parseInt(line.substring("length:".length()));
                                    char[] data = new char[len + 1];

                                    // Read intentStr
                                    log.info("Read {} length", len);
                                    int readLen = in.read(data, 0, len);
                                    data[readLen] = 0;
                                    String dataStr = new String(data);

                                    // Get to-be-modified intent (is it needed?)
                                    //                            Intent intent = app.intentService.getIntent(key);
                                    //                            if (intent == null) {
                                    //                                log.error("intent is not found: {}", key);
                                    //                                out.println("error:Not found");
                                    //                                out.flush();
                                    //                                continue;
                                    //                            }

                                    try {
                                        log.info("Parse data: {} ({} length)", dataStr, readLen);
                                        ObjectNode root = (ObjectNode) context.mapper().readTree(dataStr);

                                        log.info("Decode Json into intent: {}", root.toString());
                                        Intent intent = context.codec(Intent.class).decode(root, context);

                                        log.info("Submit intent to service");
                                        app.intentService.submit(intent);
                                        if (!intent.key().equals(key)) {
                                            log.error("key is different - req:{} vs stored:{}", key, intent.key());
                                            out.println("error:Not found");
                                        } else {
                                            log.info("Send intent key: {}", intent.key().toString());
                                            out.println("key:" + intent.key());
                                        }
                                    } catch (Exception e) {
                                        out.println("error:unsupported intent: " + e.getMessage());
                                    }

                                } else {
                                    out.printf("error:wrong request message %s%n", line);
                                }

                                break;
                            }
                            case "WITHDRAW":
                            case "PURGE":
                            case "GET": {
                                String line = in.readLine().trim();

                                // Get AppId
                                if (!line.startsWith("appId:")) {
                                    out.printf("error:wrong request message %s%n", line);
                                    out.flush();
                                    continue;
                                }
                                String appIdStr = line.substring("appId:".length());
                                final ApplicationId appId = app.coreService.getAppId(appIdStr);
                                if (appId == null) {
                                    out.printf("error:wrong appId %s%n", appIdStr);
                                    out.flush();
                                    continue;
                                }

                                // Get Key
                                line = in.readLine().trim();
                                if (!line.startsWith("key:")) {
                                    out.printf("error:wrong request message %s%n", line);
                                    out.flush();
                                    continue;
                                }
                                String keyStr = line.substring("key:".length());

                                // Get final key from keyStr and appId
                                Key key = Key.of(Long.decode(keyStr), appId);
                                log.info("{} intent appId:{}, key:{}", command, appIdStr, keyStr);

                                // Get intent
                                Intent intent = app.intentService.getIntent(key);
                                if (intent == null) {
                                    log.error("intent is not found: {}", key);
                                    out.println("error:Not found");

                                } else if (command.equals("WITHDRAW")) {
                                    log.info("Withdraw intent");
                                    app.intentService.withdraw(intent);
                                    out.println("key:" + intent.id());

                                } else if (command.equals("PURGE")) {
                                    log.info("Purge intent");
                                    app.intentService.purge(intent);
                                    out.println("key:" + intent.id());

                                } else if (command.equals("GET")) {
                                    final ObjectNode root;
                                    if (intent instanceof HostToHostIntent) {
                                        root = context.codec(HostToHostIntent.class).encode((HostToHostIntent) intent, context);
                                    } else if (intent instanceof PointToPointIntent) {
                                        root = context.codec(PointToPointIntent.class).encode((PointToPointIntent) intent, context);
                                    } else if (intent instanceof SinglePointToMultiPointIntent) {
                                        root = context.codec(SinglePointToMultiPointIntent.class).encode((SinglePointToMultiPointIntent) intent, context);
                                    } else if (intent instanceof MultiPointToSinglePointIntent) {
                                        root = context.codec(MultiPointToSinglePointIntent.class).encode((MultiPointToSinglePointIntent) intent, context);
                                    } else {
                                        root = context.codec(Intent.class).encode(intent, context);
                                    }

                                    String intentStr = root.toString();

                                    out.println("length:" + intentStr.length());
                                    out.write(intentStr.getBytes(), 0, intentStr.length());
                                }

                                break;
                            }
                            default:
                                out.println("error:Unsupported command: " + command);
                                break;
                        }

                        out.flush();
                    }
                } catch (SocketException e) {
                    in.close();
                    out.close();
                    socket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
