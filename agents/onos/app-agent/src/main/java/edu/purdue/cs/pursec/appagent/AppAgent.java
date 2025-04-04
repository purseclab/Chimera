/*
 * Copyright 2023-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.purdue.cs.pursec.appagent;

import com.google.gson.JsonObject;
import org.onosproject.codec.CodecService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import p4testgen.P4Testgen;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true)
public class AppAgent {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CodecService codecService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiPipeconfService piPipeconfService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;

    private static final int DROP_RULE_TIMEOUT = 300;
    private static final String TEST_AGENT_PORT = "5000";
    private static final String TEST_AGENT_ADDR = "127.0.0.1";
    private static final String TEST_AGENT_SNIFF_RESULT_ROUTE = "/sniff_result";
    private static final int P4_DEFAULT_CONTROLLER_PORT = 255;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
            IntentState.WITHDRAWING,
            IntentState.WITHDRAW_REQ);

    private AppInterface appInterface;

    public Map<String, Map<String, List<P4Testgen.OutputPacketAtPort>>> expectedPacketMultiMap = new ConcurrentHashMap<>();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("edu.purdue.cs.pursec.app-agent");

        packetService.addProcessor(processor, PacketProcessor.director(2));

//        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
//        selector.matchEthType(Ethernet.TYPE_IPV4);
//        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        appInterface = new AppInterface(this);
        appInterface.start();

        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(processor);

        if (appInterface != null)
            appInterface.stop();
        log.info("Stopped");
    }

    public ApplicationId getAppId() {
        return appId;
    }

    private class ReactivePacketProcessor implements PacketProcessor {

        private boolean comparePacket(InboundPacket pkt, P4Testgen.OutputPacketAtPort expPkt) {
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PiPipeconf pipeconf = piPipeconfService.getPipeconf(deviceId).orElse(null);
            if (pipeconf == null)
                return false;


            PortNumber inputPort = pkt.receivedFrom().port();

            byte[] maskBytes = expPkt.getPacketMask().toByteArray();
            byte[] expBytes = expPkt.getPacket().toByteArray();

            if (pipeconf.id().toString().equals("org.onosproject.pipelines.basic") ||
                    pipeconf.id().toString().equals("org.onosproject.pipelines.int")) {
                BigInteger expMetadataValue = new BigInteger(new byte[]{expBytes[0], expBytes[1]});
                // Get outputPort from [9-bit metadata][7-bit padding]
                BigInteger expInputPort = expMetadataValue.shiftRight(7).and(BigInteger.valueOf(0x1ff));
                if (!inputPort.equals(PortNumber.portNumber(expInputPort.longValue()))) {
                    log.warn("received port ({}) is different from expected ({})",
                            inputPort, expInputPort.longValue());
                    return false;
                }

                // Pop out the front two-byte header
                maskBytes = Arrays.copyOfRange(maskBytes, 2, maskBytes.length);
                expBytes = Arrays.copyOfRange(expBytes, 2, expBytes.length);

            } else if (pipeconf.id().toString().startsWith("org.stratumproject.fabric")) {
                BigInteger expMetadataValue = new BigInteger(new byte[]{expBytes[0], expBytes[1]});
                // Get outputPort from [7-bit padding][9-bit metadata]
                BigInteger expInputPort = expMetadataValue.and(BigInteger.valueOf(0x1ff));
                if (!inputPort.equals(PortNumber.portNumber(expInputPort.longValue()))) {
                    log.warn("received port ({}) is different from expected ({})",
                            inputPort, expInputPort.longValue());
                    return false;
                }

                // Pop out the front two-byte header
                maskBytes = Arrays.copyOfRange(maskBytes, 2, maskBytes.length);
                expBytes = Arrays.copyOfRange(expBytes, 2, expBytes.length);
            }

            byte[] rawPkt = pkt.unparsed().array();
            if (rawPkt.length < maskBytes.length) {
                log.warn("received packet ({}) is shorter than expected ({})",
                        rawPkt.length, maskBytes.length);
                return false;
            }

            boolean found = true;
            for (int i = 0; i < maskBytes.length; i++) {
                if ((maskBytes[i] & rawPkt[i]) != expBytes[i]) {
                    found = false;
                    log.warn("received packet at {} ({}) is different from expected ({})",
                            i, String.format("0x%02x", maskBytes[i] & rawPkt[i]),
                            String.format("0x%02x", expBytes[i]));
                    break;
                }
            }

            return found;
        }

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do anymore to it.
            if (context.isHandled())
                return;

            InboundPacket pkt = context.inPacket();

            byte[] rawPkt = pkt.unparsed().array();
            if (rawPkt.length == 0)
                return;

            String deviceId = pkt.receivedFrom().deviceId().toString();
            PortNumber inputPort = pkt.receivedFrom().port();

            log.debug("Rx packet in {}/{}: {}", deviceId, inputPort, pkt.parsed());
            // Expected one
            for (String actionId : expectedPacketMultiMap.keySet()) {
                Map<String, List<P4Testgen.OutputPacketAtPort>> expectedPacketMap = expectedPacketMultiMap.get(actionId);
                if (expectedPacketMap == null)
                    continue;

                // skip non-related map
                List<P4Testgen.OutputPacketAtPort> expectedPackets = expectedPacketMap.get(deviceId +
                        "/" + inputPort.toLong());
                if (expectedPackets == null)
                    continue;

                final Iterator<P4Testgen.OutputPacketAtPort> each = expectedPackets.iterator();
                while (each.hasNext()) {
                    P4Testgen.OutputPacketAtPort expectedPkt = each.next();
                    if (comparePacket(pkt, expectedPkt)) {
                        log.debug("remove packet");
                        each.remove();
                    }
                }

                if (expectedPackets.isEmpty()) {
                    JsonObject retJson = new JsonObject();
                    StringTokenizer st = new StringTokenizer(actionId, "-");
                    String seq = "";
                    if (st.hasMoreTokens()) {
                        seq = st.nextToken();
                    }
                    String key = actionId.substring(seq.length() + 1);
                    retJson.addProperty("key", key);
                    retJson.addProperty("actionId", key);
                    retJson.addProperty("seq", seq);
                    retJson.addProperty("dst", deviceId + "/" + P4_DEFAULT_CONTROLLER_PORT);
                    retJson.addProperty("result", "success");

                    String urlBuilder = "http://" + TEST_AGENT_ADDR +
                            ":" + TEST_AGENT_PORT +
                            TEST_AGENT_SNIFF_RESULT_ROUTE;
                    String url = urlBuilder.replaceAll("\\s+", "");

                    try {
                        // Request Device REST
                        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                        conn.setRequestMethod("POST");
                        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                        conn.setRequestProperty("Accept", "application/json");
                        conn.setDoOutput(true);

                        OutputStream os = conn.getOutputStream();

                        os.write(retJson.toString().getBytes("utf-8"));
                        log.debug(retJson.toString());
                        os.close();

                        int responseCode = conn.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            log.error("[{}] Failed: {}", responseCode, url);
                        }
                    } catch (IOException e) {
                        log.error("Failed: {}", e.getMessage());
                    }
                }
            }
        }
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(),
                treatment, context.inPacket().unparsed());
        packetService.emit(packet);
        log.info("sending packet: {}", packet);
    }

    // Install a rule forwarding the packet to the specified port.
    private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

        Key key;
        if (srcId.toString().compareTo(dstId.toString()) < 0) {
            key = Key.of(srcId.toString() + dstId.toString(), appId);
        } else {
            key = Key.of(dstId.toString() + srcId.toString(), appId);
        }

        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
        // TODO handle the FAILED state
        if (intent != null) {
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            } else if (intentService.getIntentState(key) == IntentState.FAILED) {

                TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
            }

        } else if (intent == null) {
            HostToHostIntent hostIntent = HostToHostIntent.builder()
                    .appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
                    .build();

            intentService.submit(hostIntent);
        }

    }

}