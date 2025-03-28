package edu.purdue.cs.pursec.ifuzzer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.P4ToolConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.comm.impl.ONOSAgentInterface;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionP4TestContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.DpAgentProxy;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.TestIntent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl.PazzIntentPacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEventListener;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.HostToHostIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.PointToPointIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreListener;
import edu.purdue.cs.pursec.ifuzzer.store.api.ScenarioEvent;
import edu.purdue.cs.pursec.ifuzzer.store.impl.RuleStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.ConfigTopo;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ChimeraTTF;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import fi.iki.elonen.router.RouterNanoHTTPD;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.*;

public class NetworkTestManager extends RouterNanoHTTPD {
    private static Logger log = LoggerFactory.getLogger(NetworkTestManager.class);
    private static TopoGraph topoGraph;
    private static TopoGraph configTopoGraph;
    private static RuleStore ruleStore;
    private static IntentStore intentStore;
    private static ScenarioStore scenarioStore;
    private static FlowRuleStore flowRuleStore;
    private static final String[] topologyJsonKeys = {"topo", "switch", "host", "chassis-config-file"};
    private static ConfigTopo configTopo;
    private static Map<TopoOperation, AtomicLong> topoOperationWaitMap = new ConcurrentHashMap<>();
    private static ConfigTopo configHosts = new ConfigTopo();
    private static IntentInterface intentInterface;

    private static Map<String, String> logMessageMap = new ConcurrentHashMap<>();

    public NetworkTestManager(TopoGraph topoGraph, TopoGraph configTopoGraph,
                              RuleStore ruleStore, IntentStore intentStore,
                              ScenarioStore scenarioStore, FlowRuleStore flowRuleStore,
                              IntentInterface intentInterface) {
        super(5050);
        this.topoGraph = topoGraph;
        this.ruleStore = ruleStore;
        this.intentStore = intentStore;
        this.scenarioStore = scenarioStore;
        this.configTopo = new ConfigTopo();
        NetworkTestManager.intentInterface = intentInterface;
        NetworkTestManager.configTopoGraph = configTopoGraph;
        NetworkTestManager.flowRuleStore = flowRuleStore;

        scenarioStore.addListener(new InternalScenarioListener());
        topoGraph.addListener(new InternalTopoGraphListener());
        intentStore.addListener(new InternalIntentListener());
    }

    public void start() {
        try {
            addMappings();
            start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /*
     * REST API Server
     */

    @Override
    public void addMappings() {
        addRoute(TestConstants.TEST_CONFIG_TOPO_ROUTE, ConfigTopoHandler.class);
        addRoute(TestConstants.TEST_RET_ROUTE, SniffResultHandler.class);
        addRoute(TestConstants.TEST_PACKET_RET_ROUTE, SniffPacketResultHandler.class);
    }

    public static class ConfigTopoHandler extends GeneralHandler {
        @Override
        public Response post(UriResource uriResource, Map<String, String> urlParams, IHTTPSession session) {
            Map<String, String> body = new HashMap<>();

            try {
                session.parseBody(body);
                log.debug("[POST] received: " + body.toString());

                if (body.get("postData") != null) {
                    JsonObject jsonObject = JsonParser.parseString(body.get("postData")).getAsJsonObject();
                    String errorMsg = TestUtil.jsonToConfigTopo(configTopo, jsonObject);
                    TestUtil.storeGraph(configTopoGraph, jsonObject);

                    log.debug("[{}] {}", configTopo.getActionId(), configTopo.getSummary());

                    if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty())
                        deliverNetcfg();

                    if (configTopo.areAllDevicesChecked() && configTopo.areAllLinksChecked()) {
                        scenarioStore.finishAction(configTopo.getActionId(), 0);
                        configTopo.setActionId(null);
                    }
                }

                return newFixedLengthResponse(session.getQueryParameterString());

            } catch (IOException ioe) {
                scenarioStore.failAction(configTopo.getActionId(), 0, ioe.getMessage());
                log.error(ioe.getMessage());
                return newFixedLengthResponse(Status.INTERNAL_ERROR, MIME_PLAINTEXT,
                        "SERVER INTERNAL ERROR: Exception: " + ioe.getMessage());

            } catch (ResponseException re) {
                scenarioStore.failAction(configTopo.getActionId(), 0, re.getMessage());
                log.error(re.getMessage());
                return newFixedLengthResponse(re.getStatus(), MIME_PLAINTEXT,
                        re.getMessage());
            }
        }
    }

    public static class SniffPacketResultHandler extends GeneralHandler {
        @Override
        public Response post(UriResource uriResource, Map<String, String> urlParams, IHTTPSession session) {
            Map<String, String> body = new HashMap<>();

            try {
                session.parseBody(body);
                log.debug("[POST] received: " + body);
                String key = null;
                String result = null;
                String actionId = null;
                String seq = null;

                if (body.get("postData") != null) {
                    JsonObject jObject = JsonParser.parseString(body.get("postData")).getAsJsonObject();
                    if (jObject.get("key") != null)
                        key = jObject.get("key").getAsString();
                    if (jObject.get("result") != null)
                        result = jObject.get("result").getAsString();
                    if (jObject.get("actionId") != null)
                        actionId = jObject.get("actionId").getAsString();
                    if (jObject.get("seq") != null)
                        seq = jObject.get("seq").getAsString();
                } else {
                    // body.get("seq");
                    key = body.get("key");
                    result = body.get("result");
                    actionId = body.get("actionId");
                    seq = body.get("seq");
                }

                int seqNum = 0;
                if (seq != null)
                    seqNum = Integer.parseInt(seq);

                if (intentInterface instanceof ONOSAgentInterface) {
                    ((ONOSAgentInterface)intentInterface).clearPacket(actionId, seqNum);
                }

                if (result.equals("success")) {
                    Set<ChimeraTTF> curTTFList = scenarioStore.getFoundTTFs(actionId, seqNum);
                    if (curTTFList.contains(ChimeraTTF.ONOS_BUG_CONTROLLER_HOST))
                                scenarioStore.finishAction(actionId, seqNum, false, "");
                    else
                        scenarioStore.finishAction(actionId, seqNum, false, "",
                                null, ChimeraTTF.NO_BUG);
                } else {
                    String logMsg = result;
                    if (logMessageMap.containsKey(actionId + seq)) {
                        logMsg += ", " + logMessageMap.remove(actionId + seq);
                    }
                    scenarioStore.failAction(actionId, seqNum, logMsg, true);
                }

                return newFixedLengthResponse(session.getQueryParameterString());
            } catch (IOException ioe) {
                log.error(ioe.getMessage());
                return newFixedLengthResponse(Status.INTERNAL_ERROR, MIME_PLAINTEXT,
                        "SERVER INTERNAL ERROR: Exception: " + ioe.getMessage());

            } catch (ResponseException re) {
                log.error(re.getMessage());
                return newFixedLengthResponse(re.getStatus(), MIME_PLAINTEXT,
                        re.getMessage());
            }
        }
    }
    public static class SniffResultHandler extends GeneralHandler {

        @Override
        public Response post(UriResource uriResource, Map<String, String> urlParams, IHTTPSession session) {
            Map<String, String> body = new HashMap<>();

            try {
                session.parseBody(body);
                log.debug("[POST] received: " + body.toString());
                String key = null;
                String result = null;
                String actionId = null;
                String seq = null;
                boolean sflow = false;

                if (body.get("postData") != null) {
                    JsonObject jObject = JsonParser.parseString(body.get("postData")).getAsJsonObject();
                    if (jObject.get("key") != null)
                        key = jObject.get("key").getAsString();
                    if (jObject.get("result") != null)
                        result = jObject.get("result").getAsString();
                    if (jObject.get("actionId") != null)
                        actionId = jObject.get("actionId").getAsString();
                    if (jObject.get("seq") != null)
                        seq = jObject.get("seq").getAsString();
                    if (jObject.has("sflow"))
                        sflow = jObject.get("sflow").getAsBoolean();
                } else {
                    // body.get("seq");
                    key = body.get("key");
                    result = body.get("result");
                    actionId = body.get("actionId");
                    seq = body.get("seq");
                }

                int seqNum = 0;
                if (seq != null)
                    seqNum = Integer.parseInt(seq);

                if (sflow)
                    intentStore.updateIntent(key, seqNum, Type.STOP_TEST, actionId);

                log.debug("{}, {}, {}", key, result, actionId);
                if (key != null && result != null) {
                    Intent intent = intentStore.getIntent(key);
                    if (intent != null) {
                        boolean testSuccess = result.equals("success");
                        if (testSuccess == State.INSTALLED.equals(intent.getState())) {
                            /* TODO: support multiple intents */
                            intentStore.updateIntent(key, seqNum, Type.DONE, actionId);
                        } else if (testSuccess) {
                            intentStore.failTestIntent(key, seqNum, actionId,
                                    intent.getState().toString() + ": success");
                        } else {
                            intentStore.failTestIntent(key, seqNum, actionId,
                                    "INSTALLED: " + result);
                        }
                    }
                }

                return newFixedLengthResponse(session.getQueryParameterString());

            } catch (IOException ioe) {
                log.error(ioe.getMessage());
                return newFixedLengthResponse(Status.INTERNAL_ERROR, MIME_PLAINTEXT,
                        "SERVER INTERNAL ERROR: Exception: " + ioe.getMessage());

            } catch (ResponseException re) {
                log.error(re.getMessage());
                return newFixedLengthResponse(re.getStatus(), MIME_PLAINTEXT,
                        re.getMessage());
            }
        }
    }

    /*
     * Commands for test-agent
     */

    public boolean startAgent(JsonObject content) throws IOException, InterruptedException {

        if (!content.has("configTopo"))
            return false;

        Runtime run = Runtime.getRuntime();
        StringBuilder command = new StringBuilder("python3 ").append(IFuzzer.rootPath).append("/agents/test-agent.py start");

        command.append(" --fuzzer_url=").append(TestConstants.TEST_MANAGER_URL).append(TestConstants.TEST_CONFIG_TOPO_ROUTE);
//        command += " --discover_host";
        command.append(" --data_net=").append(TestConstants.TEST_DATA_SUBNET);
        command.append(" --mgmt_net=").append(TestConstants.TEST_MGMT_SUBNET);
        command.append(" --switch-log-level=").append(TestConstants.TEST_SWITCH_LOG_LEVEL);

        JsonObject topoJson = content.get("configTopo").getAsJsonObject();
        for (String topologyJsonKey : topologyJsonKeys) {
            if (topoJson.has(topologyJsonKey)) {
                String topoJsonVal = topoJson.get(topologyJsonKey).getAsString();
                command.append(" --").append(topologyJsonKey).append("=").append(topoJsonVal);
                if (topologyJsonKey.equals("topo") && topoJsonVal.equals("single") &&
                        !ConfigConstants.CONFIG_P4_PIPELINE.isEmpty()) {
                    command.append(" --switch-ip=").append(P4ToolConstants.getRemoteSwitchIP());
                    command.append(" --switch-port=").append(P4ToolConstants.getRemoteSwitchPort());
                }
            }
        }

        if (content.has("controllerIp"))
            command.append(" --controller=").append(content.get("controllerIp").getAsString());

        command.append(" --path=").append(IFuzzer.workDir().toString()).append("/agents");

        if (ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance")) {
            command.append(" -z");
            if (!ConfigConstants.CONFIG_PAZZ_CONSISTENCY_TESTER_IP.isEmpty()) {
                command.append(" --ct=").append(ConfigConstants.CONFIG_PAZZ_CONSISTENCY_TESTER_IP);
            }
        } else if (ConfigConstants.CONFIG_ENABLE_STATIC_MIRROR) {
            // NOTE: PAZZ cannot use static_mirror
            command.append(" --static_mirror");
        }

        if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty()) {
            command.append(" -D bmv2 -P ").append(ConfigConstants.CONFIG_P4_PIPELINE);
        }

        // Execute mininet
        log.debug("Execute {}", command.toString());
        Process pr = run.exec(command.toString());
        pr.waitFor();

//        if (getPidAgent() < 0) {
//            BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getErrorStream()));
//            reader.lines().forEach(log::error);
//            log.error("FAIL while starting agent");
//            return false;
//        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getErrorStream()));
        reader.lines().forEach(log::error);
        reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        reader.lines().forEach(log::debug);
        return true;
    }

    public boolean stopAgent() throws IOException, InterruptedException {
        Runtime run = Runtime.getRuntime();

        String command = "python3 " + IFuzzer.rootPath + "/agents/test-agent.py stop";
        Process pr = run.exec(command);
        pr.waitFor();

        if (TestUtil.getTestAgentPid() >= 0) {
            log.error("FAIL while stopping agent");
            return false;
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        reader.lines().forEach(log::debug);
        // mininet clearing log is printed in stderr
        reader = new BufferedReader(new InputStreamReader(pr.getErrorStream()));
        reader.lines().forEach(log::debug);
        return true;

    }

    private static boolean deliverNetcfg() throws IOException {

        JsonObject netcfgJson = TestUtil.requestNetCfgJson();
        if (netcfgJson == null)
            return false;

        HttpURLConnection conn = ONOSUtil.setNetcfgToONOS(netcfgJson);
        int responseCode = conn.getResponseCode();

        return (responseCode >= 200 && responseCode < 300);
    }

    /*
     * Listeners
     */
    private class InternalTopoGraphListener implements TopoGraphListener {
        @Override
        public void event(TopoGraphEvent event) {
            log.debug("Event {} {}", event.getType().name(), event.getElem().toJson());
            // Check if this event is happened due to topoOperation
            for (TopoOperation topoOperation : topoOperationWaitMap.keySet()) {
                if (topoOperation.getType().equals(TopoOperation.Type.ADD)) {
                    if (!event.getType().equals(TopoGraphEvent.Type.PUT))
                        continue;
                }

                if (topoOperation.getType().equals(TopoOperation.Type.DELETE)) {
                    if (!event.getType().equals(TopoGraphEvent.Type.REMOVE))
                        continue;
                }

                List<String> changedIntents = new ArrayList<>();
                TopoElem topoElem = event.getElem();
                if ((topoElem instanceof TopoLink) &&
                        (topoOperation.getElem() instanceof TopoLink)) {
                    // TODO: support multi-link
                    TopoLink topoEventLink = (TopoLink) topoElem;
                    TopoLink topoOperationLink = (TopoLink) topoOperation.getElem();
                    long counter = 0;

                    // There may be duplicated events (two identical link-add events)
                    if (topoEventLink.getSrcId().equals(topoOperationLink.getSrcId()) &&
                            topoEventLink.getDstId().equals(topoOperationLink.getDstId())) {
                        counter = topoOperationWaitMap.computeIfAbsent(topoOperation, k -> new AtomicLong(0))
                                .accumulateAndGet(1, (x, y) -> (x | y));
                        log.debug("Link one: OPER {} vs EVENT {}", topoOperationLink.toJson().toString(),
                                topoEventLink.toJson().toString());

                    } else if (topoEventLink.getSrcId().equals(topoOperationLink.getDstId()) &&
                            topoEventLink.getDstId().equals(topoOperationLink.getSrcId())) {
                        counter = topoOperationWaitMap.computeIfAbsent(topoOperation, k -> new AtomicLong(0))
                                .accumulateAndGet(2, (x, y) -> (x | y));
                        log.debug("Link two: OPER {} vs EVENT {}", topoOperationLink.toJson().toString(),
                                topoEventLink.toJson().toString());

                    } else {
                        // Not found
                        log.debug("Not Found: OPER {} vs EVENT {}", topoOperationLink.toJson().toString(),
                                topoEventLink.toJson().toString());
                        continue;
                    }

                    /* FOUND; check if all bidirectional links are found */
                    if (counter == 3) {
                        log.debug("TopoOperation is done: {}", topoOperation.getElem().toJson().toString());
                        topoOperationWaitMap.remove(topoOperation);
                        intentStore.recomputeIntents(topoGraph, changedIntents);
                        scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                false, "",
                                changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                    }

                    break;

                } else if ((topoElem instanceof TopoDevice) &&
                        (topoOperation.getElem() instanceof TopoDevice)) {
                    TopoDevice topoEventDevice = (TopoDevice) topoElem;
                    TopoDevice topoOperationDevice = (TopoDevice) topoOperation.getElem();
                    log.debug("OPER {} vs EVENT {}", topoOperationDevice.toJson().toString(),
                            topoEventDevice.toJson().toString());

                    // OpenFlow ID?
                    if (ONOSUtil.isEqualDpid(topoEventDevice.getId(), topoOperationDevice.getId())) {
                        topoOperationWaitMap.remove(topoOperation);
                        intentStore.recomputeIntents(topoGraph, changedIntents);
                        scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                false, "",
                                changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                    }

                } else if ((topoElem instanceof TopoHost) &&
                        (topoOperation.getElem() instanceof TopoHost)) {
                    TopoHost topoEventHost = (TopoHost) topoElem;
                    TopoHost topoOperationHost = (TopoHost) topoOperation.getElem();
                    log.debug("EVENT {} vs OPER {}", topoEventHost.toJson().toString(),
                            topoOperationHost.toJson().toString());

                    Set<String> topoEventHostIps = topoEventHost.getIps().stream()
                            .map(IPAddress::toString)
                            .collect(Collectors.toSet());

                    Set<String> topoOperationHostIps = topoOperationHost.getIps().stream()
                            .map(IPAddress::toString)
                            .collect(Collectors.toSet());

                    if (!topoEventHostIps.equals(topoOperationHostIps)) {
                        log.debug("  ip set is different");
                        continue;
                    }

                    // Check whether controller discovers the host in the RIGHT position
                    if (topoOperation.getDpid() != null && topoOperation.getPort() != null) {
                        // Increment 1: Host itself
                        long counter = topoOperationWaitMap.computeIfAbsent(topoOperation, k -> new AtomicLong(0))
                                .incrementAndGet();

                        if (counter == 3) {
                            log.debug("TopoOperation is done: {}", topoOperation.toString());
                            topoOperationWaitMap.remove(topoOperation);
                            intentStore.recomputeIntents(topoGraph, changedIntents);
                            scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                    false, "",
                                    changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                        }
                    } else {
                        topoOperationWaitMap.remove(topoOperation);
                        intentStore.recomputeIntents(topoGraph, changedIntents);
                        scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                false, "",
                                changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                    }
                } else if ((topoElem instanceof TopoHostEdge) &&
                        (topoOperation.getElem() instanceof TopoHost)) {
                    if (topoOperation.getDpid() == null || topoOperation.getPort() == null)
                        continue;

                    TopoHostEdge topoEventHostEdge = (TopoHostEdge) topoElem;
                    TopoHost topoOperationHost = (TopoHost) topoOperation.getElem();

                    log.debug("EVENT {} - OPER {}", topoEventHostEdge.toJson().toString(),
                            topoOperationHost.toJson().toString());

                    String dpid, dpPort;
                    if (topoEventHostEdge.getDstPort() == null) {
                        dpid = topoEventHostEdge.getSrcId();
                        dpPort = topoEventHostEdge.getSrcPort();
                    } else {
                        dpid = topoEventHostEdge.getDstId();
                        dpPort = topoEventHostEdge.getDstPort();
                    }

                    if (dpid.equals(topoOperation.getDpid()) &&
                            dpPort.equals(topoOperation.getPort())) {
                        // Increment 2, 3: Host edges
                        long counter = topoOperationWaitMap.computeIfAbsent(topoOperation, k -> new AtomicLong(0))
                                .incrementAndGet();

                        if (counter == 3) {
                            log.debug("TopoOperation is done: {}", topoOperation.toString());
                            topoOperationWaitMap.remove(topoOperation);
                            intentStore.recomputeIntents(topoGraph, changedIntents);
                            scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                    false, "",
                                    changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                        }
                    }
                }
            }

            if (event.getType().equals(TopoGraphEvent.Type.PUT)) {
                TopoElem topoElem = event.getElem();

                if (topoElem instanceof TopoDevice) {
                    TopoDevice topoDevice = (TopoDevice) topoElem;
                    if (topoDevice.getState().equals(TopoElem.State.ACTIVE))
                        configTopo.checkDevice(topoDevice.getId());
                } else if (topoElem instanceof TopoLink) {
                    TopoLink topoLink = (TopoLink) topoElem;
                    if (topoLink.getState().equals(TopoElem.State.ACTIVE))
                        configTopo.checkLink(topoLink.getId());
                } else if (topoElem instanceof TopoHost) {
                    TopoHost topoHost = (TopoHost) topoElem;
                    if (topoHost.getState().equals(TopoElem.State.ACTIVE)) {
                        configHosts.checkHost(topoHost.getMac().toString(), topoHost.getId());
                    }
                } else {
                    return;
                }

                log.debug("[{}] {} / {} links in topograph", configTopo.getActionId(), configTopo.getSummary(),
                        topoGraph.getAllEdges().size());

                // Check whether the whole topology is detected.
                if (configTopo.areAllDevicesChecked() && configTopo.areAllLinksChecked()) {
                    scenarioStore.finishAction(configTopo.getActionId(), 0);
                    configTopo.setActionId(null);
                }

                if (configHosts.areAllHostsChecked()) {
                    scenarioStore.finishAction(configHosts.getActionId(), 0);
                    configHosts.setActionId(null);
                }
            } else if (event.getType().equals(TopoGraphEvent.Type.REMOVE)) {
                TopoElem topoElem = event.getElem();

                if (topoElem instanceof TopoHost) {
                    TopoHost topoHost = (TopoHost) topoElem;
                    configHosts.removeHost(topoHost.getMac().toString());
                }
            }
        }
    }

    private class InternalScenarioListener implements StoreListener<ScenarioEvent>, Runnable {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        private final Future future;
        private Map<String, Integer> waitingEvents = new ConcurrentHashMap<>();
        private int curTimeCnt = 0;

        public InternalScenarioListener() {
            future = executor.scheduleWithFixedDelay(this, 0,
                    ConfigConstants.CONFIG_TOPOLOGY_CHECK_INTERVAL_MS, TimeUnit.MILLISECONDS);
        }

        private String startSniffPacketFromController(String actionId, int seq, FuzzActionP4TestContent packetContent)
                throws ParseException {
            /* Send EXPECT_PACKET to ONOS agent */
            if (!(intentInterface instanceof ONOSAgentInterface))
                return "Set ONOS Agent";

            IntentInterfaceResponse resp = ((ONOSAgentInterface)intentInterface).expectPacket(actionId, seq,
                    ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID,
                    P4Testgen.TestCase.newBuilder()
                            .setInputPacket(packetContent.getInputPacket())
                            .addAllExpectedOutputPacket(packetContent.getOutputPacket())
                            .build());

            return resp.getErrorMsg();
        }

        private String stopSniffPacketFromController(String actionId, int seq) {
            /* Send CLEAR_PACKET to ONOS agent */
            if (!(intentInterface instanceof ONOSAgentInterface))
                return "Set ONOS Agent";

            IntentInterfaceResponse resp = ((ONOSAgentInterface)intentInterface).clearPacket(actionId, seq);

            return resp.getErrorMsg();
        }

        private String startSendPacketFromContorller(String actionId, int seq, FuzzActionP4TestContent packetContent)
                throws ParseException {
            /* Send SEND_PACKET to ONOS agent */
            if (!(intentInterface instanceof ONOSAgentInterface))
                return "Set ONOS Agent";

            IntentInterfaceResponse resp = ((ONOSAgentInterface)intentInterface).sendPacket(actionId, seq,
                    ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID,
                    P4Testgen.TestCase.newBuilder()
                            .setInputPacket(packetContent.getInputPacket())
                            .addAllExpectedOutputPacket(packetContent.getOutputPacket())
                            .build());

            return resp.getErrorMsg();
        }

        private boolean compareConfigThenStore(JsonObject configTopoJson) throws IOException {
            ConfigTopo localConfig = new ConfigTopo();
            localConfig.setConfig(configTopoJson);

            // Get topology from agent
            HttpURLConnection conn = TestUtil.requestTopology();
            int responseCode = conn.getResponseCode();
            if (responseCode < 200 || responseCode >= 300) {
                log.error("response: " + responseCode);
                return false;
            }

            JsonObject jsonObject = TestUtil.getJsonResultFromHttpConnection(conn);
            String errorMsg = TestUtil.jsonToConfigTopo(localConfig, jsonObject);
            if (errorMsg != null) {
                log.error(errorMsg);
                return false;
            }

            if (!jsonObject.has("configTopo")) {
                log.error("No configTopo in Json");
                return false;
            }

            JsonObject localConfigTopoJson = jsonObject.get("configTopo").getAsJsonObject();
            if (!localConfig.compareConfig(localConfigTopoJson)) {
                log.error("[Error] different configuration (" + localConfigTopoJson.toString() +
                        " vs " + localConfig.getConfig().toString() + ")");
                return false;
            }

            // If comparison succeeds and configTopoGraph is empty,
            // store new topo into configuration store.
            if (configTopoGraph.getAllDevices().isEmpty())
                TestUtil.storeGraph(configTopoGraph, jsonObject);
            return true;
        }

        @Override
        public void event(ScenarioEvent scenarioEvent) {
            String key = scenarioEvent.getKey();
            int seq = scenarioEvent.getSeq();
            if (scenarioEvent.getEventType().equals("APPLY")) {
                FuzzAction action = scenarioEvent.getAction();

                if (action.getActionCmd().equals("create-topo")) {
                    JsonObject configTopoJson = action.getContent().getContent().get("configTopo").getAsJsonObject();

                    try {
                        if (!TestUtil.isLocalTestAgent()) {
                            // Check whether remote agent is running.
                            if (compareConfigThenStore(configTopoJson)) {
                                if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty())
                                    deliverNetcfg();

                                scenarioStore.finishAction(action.getId(), seq);
                            } else {
                                scenarioStore.failAction(action.getId(), seq, "fail to connect agent");
                            }
                            // Return right away
                            return;
                        }

                        if (TestUtil.getTestAgentPid() > 0) {
                            boolean isSuc = compareConfigThenStore(configTopoJson);

                            if (isSuc) {
                                if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty())
                                    deliverNetcfg();

                                // TODO: check internal data of topology
                                scenarioStore.finishAction(action.getId(), seq);
                                return;

                            } else {
                                // restart test-agent
                                log.debug("Restart topology");
                                stopAgent();
                            }

                        } else {
                            log.debug("Start topology");
                        }

                        configTopo.clearAll();
                        log.debug("Create topology: " + action.getContent().toString());

                        if (startAgent(action.getContent().getContent())) {
                            configTopo.setConfig(configTopoJson);
                            if (configTopo.isDone()) {
                                scenarioStore.finishAction(action.getId(), seq);
                                configTopo.setActionId(null);
                            } else {
                                configTopo.setActionId(action.getId());
                                if (ConfigConstants.CONFIG_TOPOLOGY_WAIT_TIMEOUT > 0)
                                    waitingEvents.put(action.getId(), curTimeCnt);
                            }

                        } else {
                            scenarioStore.failAction(action.getId(), seq, "fail to start agent");
                        }

                    } catch (Exception e) {
                        log.error(e.getMessage());
                        e.printStackTrace();
                        scenarioStore.failAction(action.getId(), seq, e.getMessage());
                    }

                } else if (action.getActionCmd().equals("delete-topo")) {
                    configTopo.clearAll();
                    log.debug("Destroy topology {}", configTopo.getSummary());

                    try {
                        if (stopAgent()) {
                            // Send sync message
                            scenarioStore.finishAction(action.getId(), seq);
                        } else {
                            scenarioStore.failAction(action.getId(), seq, "fail to start agent");
                        }
                    } catch (Exception e) {
                        log.error(e.getMessage());
                        e.printStackTrace();
                        scenarioStore.failAction(action.getId(), seq, e.getMessage());
                    }

                } else if (action.getActionCmd().equals("dp-verify-rule")) {

                    if (!(action.getContent() instanceof FuzzActionP4TestContent))
                        return;

                    FuzzActionP4TestContent packetContent = (FuzzActionP4TestContent) action.getContent();
                    try {
                        int inPort = packetContent.getInputPacket().getPort();
                        boolean hasControllerInput = (inPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT);

                        // 1) Start sniff from controller (* -> CTRL)
                        boolean hasControllerOutput = false;
                        for (P4Testgen.OutputPacketAtPort outputPacketAtPort : packetContent.getOutputPacket()) {
                            int outPort = outputPacketAtPort.getPort();
                            if (outPort == ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
                                // NOTE: assume that this case could fall into ChimeraTTF.ONOS_BUG_PACKET_IN_DROP
                                if (!hasControllerInput) {
                                    scenarioStore.setFoundTTF(action.getId(), seq, ChimeraTTF.ONOS_BUG_PACKET_IN_DROP);
                                } else {
                                    scenarioStore.setFoundTTF(action.getId(), seq, ChimeraTTF.ONOS_BUG_CONTROLLER_HOST);
                                }
                                String errorMsg = startSniffPacketFromController(action.getId(), seq, packetContent);
                                if (errorMsg != null) {
                                    // 1-1) error handling
                                    scenarioStore.failAction(action.getId(), seq, errorMsg);
                                    return;

                                }

                                hasControllerOutput = true;
                            }
                        }

                        // 2) Start packet test from test-agent (Test -> *)
                        String errorMsg = null;
                        // TODO: specify device Id
                        HttpURLConnection conn = TestUtil.requestPacketTest(ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID,
                                packetContent.getInputPacket(), packetContent.getOutputPacket(),
                                key, seq, action.getId());

                        int responseCode = conn.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            // 2-1) error handling
                            errorMsg = conn.getResponseMessage();

                        } else if (hasControllerInput) {
                            // 3) Start send from controller (CTRL -> *)
                            errorMsg = startSendPacketFromContorller(action.getId(), seq, packetContent);

                            String sniffCmd;
                            if (errorMsg == null) {
                                // 4-1) Measure sniff start time from test-agent (* -> Test)
                                conn = TestUtil.requestSniffStart(key, seq, action.getId());
                                sniffCmd = "start";
                            } else {
                                // 4-2) If error occurs, stop sniffing
                                conn = TestUtil.requestSniffStop(key, seq, action.getId());
                                sniffCmd = "stop";
                            }

                            responseCode = conn.getResponseCode();
                            if (responseCode == 409) {
                                // 4-1) sniff thread has different actionId!
                                errorMsg = ((errorMsg == null) ? "" : errorMsg + ", ") +
                                        conn.getResponseMessage();

                            } else if (responseCode < 200 || responseCode >= 300) {
                                // It's possible that sniff thread has already stopped
                                log.warn("[resp] {} sniffing: {}", sniffCmd, conn.getResponseMessage());
                            }
                        }

                        // All errors handling (2-1, 3-1, 4-1)
                        if (errorMsg != null) {
                            logMessageMap.clear();      // XXX: just simply clear it
                            logMessageMap.put(action.getId() + seq, errorMsg);

                            String errorClearMsg = null;
                            if (hasControllerOutput)
                                errorClearMsg = stopSniffPacketFromController(action.getId(), seq);

                            scenarioStore.failAction(action.getId(), seq,
                                    errorMsg + ((errorClearMsg == null) ? "" : ", " + errorClearMsg));
                        }

                    } catch (IOException e) {
                        scenarioStore.failAction(action.getId(), seq, e.getMessage());
                    }

                } else if (action.getActionCmd().equals("dp-verify-intent")) {
                    log.debug("Verify intent in data plane");
                    action.setPacketType(1);

                    if (ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance")) {
                        // get flow rules from ONOS
                        // TODO: call once for multiple dp-verify-intent
                        try {
                            ONOSUtil.storeFlowRule(flowRuleStore, ONOSUtil.getFlowRulesFromONOS());
                            flowRuleStore.generateNetworkGraph(topoGraph);
                            flowRuleStore.generateInRuleList(intentStore);

                        } catch (IOException e) {
                            log.error(e.getMessage());
                            e.printStackTrace();
                            scenarioStore.failAction(action.getId(), seq, "Cannot get flows from ONOS");
                            return;
                        }
                    }
                    packetGuidance.init();

                    FuzzActionContent fuzzActionContent = action.getContent();
                    if (fuzzActionContent == null) {
                        if (ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance")) {
                            // Test all intents at once!

                            Collection<Entry<String, Intent>> intentList = intentStore.getInstalledIntentEntries().stream()
                                    .filter(k -> !k.getValue().doNotDPTest())
                                    .collect(Collectors.toList());

                            if (intentList.size() == 0) {
                                scenarioStore.failAction(action.getId(), seq, "No intent to test");
                                return;
                            }

                            scenarioStore.setWaitCnt(action.getId(), seq, intentList.size());

                            log.info("test {} intents", intentList.size());
                            AtomicInteger i = new AtomicInteger(1);
                            intentList.forEach(k -> {
                                PointToPointIntent intent1 = (PointToPointIntent) k.getValue();
                                log.info("  {}:{} {}/{} -> {}/{}", i.getAndIncrement(), intent1.getState().toString(),
                                        intent1.getSrc().getDeviceId(), intent1.getSrc().getPortNo(),
                                        intent1.getDst().getDeviceId(), intent1.getDst().getPortNo());
                                intentStore.testIntent(k.getKey(), seq, action.getId());
                            });

                            intentStore.sendEvent(seq, action.getId(), Type.RUN_TEST);

                        } else {
                            scenarioStore.failAction(action.getId(), seq, "Specify intentId in action except Pazz");
                        }
                    } else {
                        JsonObject content = fuzzActionContent.getContent();
                        if (content.has("intentId")) {
                            String intentId = fuzzActionContent.getContent().get("intentId").getAsString();
                            Intent intent = intentStore.getIntent(intentId);
                            if (intent == null) {
                                scenarioStore.failAction(action.getId(), seq, "No intent with id: " + intentId);
                                return;
                            }

                            log.debug("Intent {}: {}", intentId, intent.toString());
                            if (intent.doNotDPTest()) {
                                scenarioStore.finishAction(action.getId(), seq);
                            } else {
                                intentStore.testIntent(intentId, seq, action.getId());
                            }
                        } else {
                            scenarioStore.failAction(action.getId(), seq, "No intentId in action: " + content.toString());
                        }
                    }

                } else if (action.getActionCmd().equals("emit-packet")) {
                    log.debug("emit packet");

                    if (!(intentInterface instanceof ONOSAgentInterface)) {
                        scenarioStore.failAction(action.getId(), seq, "Cannot emit packet from ONOS", false);
                        return;
                    }

                    JsonObject content = action.getContent().getContent();
                    if (!content.has("port")) {
                        scenarioStore.failAction(action.getId(), seq, "No port", false);
                        return;
                    }
                    int portNo = content.get("port").getAsInt();
                    if (!content.has("packet")) {
                        scenarioStore.failAction(action.getId(), seq, "No packet", false);
                        return;
                    }
                    String encodePacket = content.get("packet").getAsString();

                    IntentInterfaceResponse resp = ((ONOSAgentInterface) intentInterface).emitPacketOut(action.getId(),
                            seq, ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, portNo, encodePacket);

                    if (resp.isSuccess()) {
                        scenarioStore.finishAction(action.getId(), seq);
                    } else {
                        scenarioStore.failAction(action.getId(), seq, resp.getErrorMsg(), false);
                    }

                } else if (action.getActionCmd().equals("load-hosts")) {
                    log.debug("Load hosts");

                    try {
                        configHosts.clearAll();
                        configHosts.setActionId(action.getId(), curTimeCnt);

                        // Get hosts from topoGraph
                        Set<TopoHost> hostSets = topoGraph.getAllHosts(true);
                        log.debug("graph has {} hosts", hostSets.size());
                        hostSets.forEach(k -> configHosts.checkHost(k.getMac().toString()));

                        // reduce time by checking hosts first
                        HttpURLConnection conn = TestUtil.requestTopology();
                        int responseCode = conn.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            scenarioStore.failAction(action.getId(), seq, "Fail to get topo");
                            configHosts.setActionId(null);
                            return;
                        }

                        JsonObject topoJsonResp = TestUtil.getJsonResultFromHttpConnection(conn);
                        if (topoJsonResp.has("topology")) {
                            JsonObject topoJson = topoJsonResp.get("topology").getAsJsonObject();

                            if (topoJson.has("hosts")) {
                                JsonArray hostsJsonArr = topoJson.get("hosts").getAsJsonArray();
                                log.debug("json has {} hosts", hostsJsonArr.size());
                                for (JsonElement hostJsonElem : hostsJsonArr) {
                                    JsonObject hostJson = hostJsonElem.getAsJsonObject();
                                    if (hostJson.has("mac")) {
                                        configHosts.checkHost(hostJson.get("mac").getAsString());
                                    }
                                }
                            }
                        }

                        if (configHosts.areAllHostsChecked()) {
                            log.debug("load is finished directly");
                            scenarioStore.finishAction(action.getId(), seq);
                            configHosts.setActionId(null);

                        } else {

                            // If host is not yet, send ping from all hosts
                            conn = TestUtil.requestPingAll();
                            responseCode = conn.getResponseCode();
                            if (responseCode < 200 || responseCode >= 300) {
                                scenarioStore.failAction(action.getId(), seq, "Fail to ping all");
                                configHosts.setActionId(null);
                                return;
                            }

                            JsonObject hostsJson = TestUtil.getJsonResultFromHttpConnection(conn);
                            log.debug("Load {}", hostsJson.toString());

                            // wait until all hosts are loaded
                            if (hostsJson.has("hosts")) {
                                JsonArray hostsJsonArr = hostsJson.get("hosts").getAsJsonArray();
                                log.debug("json has {} hosts", hostsJsonArr.size());
                                for (JsonElement hostJsonElem : hostsJsonArr) {
                                    JsonObject hostJson = hostJsonElem.getAsJsonObject();
                                    if (hostJson.has("mac")) {
                                        configHosts.checkHost(hostJson.get("mac").getAsString());
                                    }
                                }
                            }

                            if (configHosts.areAllHostsChecked()) {
                                log.debug("load is finished directly");
                                scenarioStore.finishAction(action.getId(), seq);
                                configHosts.setActionId(null);
                            }
                        }

                    } catch (IOException e) {
                        log.error("load failed", e);
                        scenarioStore.failAction(action.getId(), seq, e.getMessage());
                        configHosts.setActionId(null);
                    }

                } else if (action.getActionCmd().endsWith("link") ||
                        action.getActionCmd().endsWith("device") ||
                        action.getActionCmd().endsWith("host")) {
                    // e.g. add-link, delete-device, ...
                    String [] actionCmds = action.getActionCmd().split("-");
                    assert (actionCmds.length == 2);
                    JsonObject content = action.getContent().getContent();

                    TopoOperation topoOperation = null;
                    try {
                        topoOperation = new TopoOperation(action.toJsonObject());
                        topoOperation.setActionId(action.getId());
                        topoOperation.setSeq(seq);

                        log.debug("{}{}", action.getActionCmd(),
                                topoOperation.isInitOperation() ? " (init)" : "");

                        // Do not wait for initial host operations
                        if (!topoOperation.isInitOperation() ||
                                (!(topoOperation.getElem() instanceof TopoHost))) {
                            topoOperationWaitMap.put(topoOperation, new AtomicLong(0));
                        } else if (action.isSync()) {
                            topoOperationWaitMap.put(topoOperation, new AtomicLong(0));
                        }

                        HttpURLConnection conn = TestUtil.requestTopoOperation(actionCmds[0], actionCmds[1],
                                content, action.getId());

                        int responseCode = conn.getResponseCode();

                        if (responseCode >= 200 && responseCode < 300) {
                            String response = "";
                            Scanner scanner = new Scanner(conn.getInputStream());
                            while (scanner.hasNextLine()) {
                                response += scanner.nextLine();
                                response += "\n";
                            }
                            scanner.close();

                            JsonObject jsonObject = TestUtil.fromJson(response);

                            if (topoOperation.getElem() instanceof TopoHost) {
                                // update mac address
                                if (jsonObject.has("mac")) {
                                    ((TopoHost) topoOperation.getElem()).setMac(jsonObject.get("mac").getAsString());
                                }

                                if (jsonObject.has("port")) {
                                    topoOperation.setPort(jsonObject.get("port").getAsString());
                                }

                                if (jsonObject.has("dpid")) {
                                    topoOperation.setDpid(jsonObject.get("dpid").getAsString());
                                }

                                if (topoOperation.isInitOperation()) {
                                    scenarioStore.finishAction(action.getId(), seq, false, "", topoOperation);
                                }
                            } else if (topoOperation.getElem() instanceof TopoLink) {
                                // update port
                                if (jsonObject.has("src")) {
                                    JsonObject srcJson = jsonObject.get("src").getAsJsonObject();
                                    if (srcJson.has("port"))
                                        ((TopoLink) topoOperation.getElem()).setSrcPort(srcJson.get("port").getAsString());
                                }

                                if (jsonObject.has("dst")) {
                                    JsonObject dstJson = jsonObject.get("dst").getAsJsonObject();
                                    if (dstJson.has("port"))
                                        ((TopoLink) topoOperation.getElem()).setDstPort(dstJson.get("port").getAsString());
                                }
                            }
                        } else {
                            topoOperationWaitMap.remove(topoOperation);
                            scenarioStore.failAction(action.getId(), seq, "Cannot " + action.getActionCmd());
                        }
                    } catch (Exception e) {
                        if (topoOperation != null)
                            topoOperationWaitMap.remove(topoOperation);
                        scenarioStore.failAction(action.getId(), seq, e.getMessage());
                    }
                }

            } else if (scenarioEvent.getEventType().equals("CLEAR")) {
                Object content = scenarioEvent.getContent();
                // content means clearTopo
                if ((content instanceof Boolean) && (boolean)content) {
                    // Stop agent if it's running
                    int pid = TestUtil.getTestAgentPid();
                    if (pid > 0) {
                        log.info("Agent is running: {}", pid);
                        try {
                            stopAgent();
                        } catch (Exception e) {
                            log.error(e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            }
        }

        @Override
        public void run() {
            curTimeCnt ++;

            for (TopoOperation topoOperation : topoOperationWaitMap.keySet()) {
                if (topoOperation.getElem() instanceof TopoHost) {

                    log.debug("waiting topoOperation:host {}", topoOperation.toFuzzActionJson().toString());

                    try {
                        TopoHost topoHost = (TopoHost) topoOperation.getElem();
                        if (topoOperation.getType().equals(TopoOperation.Type.ADD)) {
                            // send ping
                            IPv4AddressWithMask subnet = IPv4AddressWithMask.of(TestConstants.TEST_DATA_SUBNET);
                            IPv4Address sendIp = subnet.getValue().and(subnet.getMask()).or(IPv4Address.of(1));
                            TestUtil.requestPing(topoHost.getAddr(), sendIp.toString());

                        } else {
                            // check whether host is already removed or not
                            boolean found = false;
                            for (TopoHost topoHostInGraph : topoGraph.getAllHosts(true)) {
                                if (topoHostInGraph.getIps().containsAll(topoHost.getIps())) {
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                log.info("host is already removed: {}", topoHost.toJson());
                                topoOperationWaitMap.remove(topoOperation);
                                if (topoOperation.getActionId() != null) {
                                    List<String> changedIntents = new ArrayList<>();
                                    intentStore.recomputeIntents(topoGraph, changedIntents);
                                    scenarioStore.finishAction(topoOperation.getActionId(),
                                            topoOperation.getSeq(),
                                            false,
                                            "",
                                            changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                                }

                                continue;
                            }
                        }

                        // Gather host information
                        String body = ONOSUtil.getHostsFromONOS();
                        log.debug("Get host {}", body);
                        ONOSUtil.storeGraph(topoGraph, body);

                    } catch (Exception e) {
                        log.error("Error in host rest api", e);
                    }
                } else if (topoOperation.getElem() instanceof TopoLink) {

                    // Sometimes, event precedes operation.
                    log.debug("waiting topoOperation:link {}", topoOperation.toFuzzActionJson().toString());

                    TopoLink topoOperationLink = (TopoLink) topoOperation.getElem();

                    TopoEdge edgeOne = topoGraph.getEdge(ONOSUtil.getLinkId(topoOperationLink.getSrcId(), topoOperationLink.getDstId(),
                            topoOperationLink.getSrcPort(), topoOperationLink.getDstPort()));
                    TopoEdge edgeTwo = topoGraph.getEdge(ONOSUtil.getLinkId(topoOperationLink.getDstId(), topoOperationLink.getSrcId(),
                            topoOperationLink.getDstPort(), topoOperationLink.getSrcPort()));

                    if (topoOperation.getType().equals(TopoOperation.Type.DELETE)) {
                        // If there is no edge in topoGraph, action is done.
                        if (edgeOne != null && TopoElem.State.ACTIVE.equals(edgeOne.getState())) {
                            log.debug("topoGraph has link: {}", edgeOne.toString());

                        } else if (edgeTwo != null && TopoElem.State.ACTIVE.equals(edgeTwo.getState())) {
                            log.debug("topoGraph has link: {}", edgeTwo.toString());

                        } else {
                            log.debug("already removed");
                            List<String> changedIntents = new ArrayList<>();
                            topoOperationWaitMap.remove(topoOperation);
                            intentStore.recomputeIntents(topoGraph, changedIntents);
                            scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                    false, "",
                                    changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                        }

                    } else {
                        // If there are both edges in topoGraph, action is done.
                        if (edgeOne == null || TopoElem.State.INACTIVE.equals(edgeOne.getState())) {
                            log.debug("topoGraph does not have same link");

                        } else if (edgeTwo == null || TopoElem.State.INACTIVE.equals(edgeTwo.getState())) {
                            log.debug("topoGraph does not have opposite link");

                        } else {
                            log.debug("already added");
                            List<String> changedIntents = new ArrayList<>();
                            topoOperationWaitMap.remove(topoOperation);
                            intentStore.recomputeIntents(topoGraph, changedIntents);
                            scenarioStore.finishAction(topoOperation.getActionId(), topoOperation.getSeq(),
                                    false, "",
                                    changedIntents.stream().map(k -> intentStore.getIntent(k)).collect(Collectors.toList()));
                        }
                    }
                }
            }

            if (configHosts != null && configHosts.getActionId() != null && !configHosts.areAllHostsChecked()) {
                try {

                    ONOSUtil.storeGraph(topoGraph, ONOSUtil.getHostsFromONOS());

                    int hostGraphSize = topoGraph.getAllHosts(true).size();
                    int hostConfigCnt = configHosts.getAllConfigHosts().size();
                    log.debug("Store hosts: {} in graph, {} in config", hostGraphSize, hostConfigCnt);

                    if (curTimeCnt - configHosts.getStartTime()
                            > ConfigConstants.CONFIG_TOPOLOGY_HOST_WAIT_TIMEOUT) {
                        // action is failed.
                        String actionId = configHosts.getActionId();
                        configHosts.setActionId(null);
                        scenarioStore.failAction(actionId, 0, "timeout", false);
                    }

                    if (hostGraphSize < hostConfigCnt) {
                        HttpURLConnection conn = TestUtil.requestPingAll();
                        int responseCode = conn.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            log.error("fail to request ping hosts: {}", responseCode);
                        }
                    }
                } catch (IOException e) {
                    log.error("fail to store hosts", e);
                }
            }

            if (waitingEvents.size() > 0) {
                for (String actionId : waitingEvents.keySet()) {
                    int waitedTime = curTimeCnt - waitingEvents.get(actionId);
                    log.debug("{} waited {} ms", actionId,
                            waitedTime * ConfigConstants.CONFIG_TOPOLOGY_CHECK_INTERVAL_MS);

                    if (waitedTime > ConfigConstants.CONFIG_TOPOLOGY_WAIT_TIMEOUT) {
                        configTopo.setActionId(null);
                        scenarioStore.failAction(actionId, 0, "timeout");
                        waitingEvents.remove(actionId);
                    }

                    if (configTopo.isDone()) {
                        // successAction event is sent by REST API handler or event listener.
                        waitingEvents.remove(actionId);
                    }
                }
            }
        }
    }

    private static class InternalIntentListener implements IntentEventListener, Runnable {
        // worker that sends fuzz packets
        Thread worker = null;
        // ReachabilityIntent workingIntent;
        Map<String, List<DpAgentProxy>> dpAgentProxies = new ConcurrentHashMap<>();

        public InternalIntentListener() {}

        @Override
        public void event(IntentEvent event) {
            Intent eventIntent = event.getIntent();
            int seq = event.getSeq();

            if (event.getType().equals(Type.RUN_TEST)) {
                if (worker == null || !worker.isAlive()) {
                    worker = new Thread(this);
                    worker.start();
                }
                return;
            }

            if (!(eventIntent instanceof ReachabilityIntent))
                return;

            ReachabilityIntent intent = (ReachabilityIntent) eventIntent;
            int responseCode;

            switch (event.getType()) {
                case CHECK_FAILED:
                    log.info("Check Failed {}", intent.toString());
                    // Do nothing!!!
                    break;

                case CHECKED:
                    log.info("Check Success {}", intent.toString());
                    // There is no actionId -> Test right away
                    if (event.getActionId() == null)
                        intentStore.updateIntent(event.getKey(), seq, Type.TEST_REQ, event.getActionId());
                    break;
                case TEST_FAILED:
                    log.info("Test Failed {}", intent.toString());
                    String errorMsg = event.getErrorMsg();
                    if (errorMsg == null)
                        errorMsg = "failed: " + event.getKey();

                    scenarioStore.failAction(event.getActionId(), seq, errorMsg);
                    break;

                case TEST_REQ:
                    // Start network testing
                    TestIntent testIntent = new TestIntent(intent, event.getKey(), seq, event.getActionId());
                    packetGuidance.addTestIntent(testIntent);
                    JsonObject testJson = packetGuidance.getValidTestJson(intent);

                    if (testJson == null) {
                        log.error("getTestJson failed");
                        packetGuidance.removeTestIntent(testIntent);
                        if (State.INSTALLED.equals(intent.getState()))
                            intentStore.failTestIntent(event.getKey(), seq, event.getActionId(),
                                    "INSTALLED: getTestJson fail");
                        else
                            intentStore.updateIntent(event.getKey(), seq, Type.DONE, event.getActionId());
                        return;
                    }

                    try {
                        HttpURLConnection conn = TestUtil.requestTest(testJson, event.getKey(), seq, event.getActionId(),
                                intent.getRESTRoute());
                        responseCode = conn.getResponseCode();
                        boolean testSuccess = (responseCode >= 200 && responseCode < 300);

                        // TODO: sniff-result REST server can be faster than the following code
                        if (testSuccess) {
                            log.info("[{}: {}] requestDPTest {}", event.getActionId(), responseCode, intent.toString());
                        } else {
                            log.info("requestDPTest failed {}: {}", responseCode, conn.getResponseMessage());
                        }

                        State state = intent.getState();
                        if (intent instanceof HostToHostIntent) {

                            if (testSuccess == state.equals(State.INSTALLED)) {
                                /* TODO: support multiple intents */
                                intentStore.updateIntent(event.getKey(), seq, Type.DONE, event.getActionId());
                            } else if (testSuccess) {
                                intentStore.failTestIntent(event.getKey(), seq, event.getActionId(),
                                        state.toString() + ": success");
                            } else {
                                intentStore.failTestIntent(event.getKey(), seq, event.getActionId(),
                                        "INSTALLED: test fail - " + responseCode);
                            }

                        } else if (!testSuccess) {
                            if (state.equals(State.INSTALLED)) {
                                intentStore.failTestIntent(event.getKey(), seq, event.getActionId(),
                                        "INSTALLED: test fail - " + responseCode);
                            } else {
                                intentStore.updateIntent(event.getKey(), seq, Type.DONE, event.getActionId());
                            }

                        } else if (packetGuidance instanceof PazzIntentPacketGuidance) {
                            // Start packet fuzzing.
                            // NOTE: add-intent with sync option may call two dp-verify-tests
                            JsonObject jsonObject = TestUtil.getJsonResultFromHttpConnection(conn);
                            if (jsonObject.has("mgmtSrcList")) {
                                JsonArray mgmtSrcList = jsonObject.get("mgmtSrcList").getAsJsonArray();
                                List<DpAgentProxy> dpAgentProxyList = StreamSupport.stream(mgmtSrcList.spliterator(), true)
                                        .map(k -> new DpAgentProxy(k.getAsJsonObject()))
                                        .collect(Collectors.toList());

                                this.dpAgentProxies.put(event.getKey(), dpAgentProxyList);
                            }
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    break;
                case DONE:
                    log.info("Test Success {}", intent.toString());
                    scenarioStore.finishAction(event.getActionId(), seq, "VERIFIED");
                    break;

                case STOP_TEST:
                    if (worker != null && worker.isAlive()) {
                        // TODO: support multiple-intent dp-verify-test
                        log.info("Stop Fuzz {}", intent.toString());
                        this.dpAgentProxies.clear();
                        this.worker.interrupt();
                    } else {
                        log.warn("No worker to be stopped {}", intent.toString());
                    }
                    break;
                default:
                    break;
            }
        }

        private void endFuzz(TestIntent testIntent) {
            String key = testIntent.getKey();
            int seq = testIntent.getSeq();
            String actionId = testIntent.getActionId();

            try {
                HttpURLConnection conn = TestUtil.requestPazzResult(key, seq, actionId);
                JsonObject jsonObject = TestUtil.getJsonResultFromHttpConnection(conn);
                log.info("[{}] {} End Fuzz for Intent {}: {}", conn.getResponseCode(), actionId,
                        key, jsonObject.toString());
                if (jsonObject.has("result") &&
                        jsonObject.get("result").getAsString().equals("fail")) {
                    intentStore.failTestIntent(key, seq, actionId, "fail");
                } else {
                    intentStore.updateIntent(key, seq, Type.DONE, actionId);
                }
            } catch (Exception e) {
                intentStore.failTestIntent(key, seq, actionId, e.getMessage());
            }
        }

        @Override
        public void run() {
            while (!Thread.interrupted() && !dpAgentProxies.isEmpty()) {
                JsonObject testJson;
                try {
                    testJson = packetGuidance.getRandomPacketJson();

                } catch (EndFuzzException e) {
                    packetGuidance.getTestIntents().forEach(this::endFuzz);
                    dpAgentProxies.clear();
                    break;
                }

                // Send packet to DP-Agent based on Packet Fuzzing!
                if (!testJson.has("key"))
                    continue;
                String key = testJson.get("key").getAsString();
                if (!dpAgentProxies.containsKey(key))
                    continue;

                Iterator<DpAgentProxy> it = dpAgentProxies.get(key).iterator();
                while (it.hasNext()) {
                    try {
                        DpAgentProxy dpAgentProxy = it.next();
                        HttpURLConnection conn = TestUtil.requestSend(testJson, dpAgentProxy);
                        log.info("[{}] Send: {}/{} {}", conn.getResponseCode(),
                                dpAgentProxy.getMgmt(), dpAgentProxy.getIface(),
                                testJson.get("dst").getAsString());
                    } catch (IOException e) {
                        log.info("send fail: {}", e.getMessage());
                        it.remove();
                    }
                }
            }
        }
    }
}
