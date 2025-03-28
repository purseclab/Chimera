package edu.purdue.cs.pursec.ifuzzer;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.comm.impl.ONOSAgentInterface;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ONOSIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionP4TestContent;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreListener;
import edu.purdue.cs.pursec.ifuzzer.store.api.ScenarioEvent;
import edu.purdue.cs.pursec.ifuzzer.store.impl.RuleStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import java.net.HttpURLConnection;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class IntentFuzzerService {
    private static Logger log = LoggerFactory.getLogger(IntentFuzzerService.class);

    private final static int REPLAY1_REQUIRED_HOST_NUM = 6;
    private final static TopoGraphListener topoListener = new InternalTopologyListener();

    private final TopoGraph graph;

    private final RuleStore ruleStore;
    private final IntentStore intentStore;
    private final ScenarioStore scenarioStore;
    private final IntentInterface intentInterface;

    public IntentFuzzerService(TopoGraph graph, RuleStore ruleStore, IntentStore intentStore,
                               ScenarioStore scenarioStore, IntentInterface intentInterface) {
        this.graph = graph;
        this.ruleStore = ruleStore;
        this.intentStore = intentStore;
        this.scenarioStore = scenarioStore;
        this.intentInterface = intentInterface;

        graph.addListener(topoListener);
        scenarioStore.addListener(new InternalScenarioListener());
    }

    public void start() {
        String body = null;
        try {
            body = ONOSUtil.getIntentsFromONOS();
            ONOSUtil.storeIntent(intentStore, body);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Intent randomHostToHostIntent() {
        Random rand = new Random();
        Set<TopoHost> hosts = graph.getAllHosts(true);
        if (hosts.size() == 0)
            return null;

        int srcIdx = rand.nextInt(hosts.size());
        int dstIdx = rand.nextInt(hosts.size());

        TopoHost src = null, dst = null;

        int idx = 0;
        for (TopoHost host : hosts) {
            if (idx == srcIdx)
                src = host;

            if (idx == dstIdx)
                dst = host;

            idx ++;
        }

        if (src == null || dst == null) {
            log.error("Cannot create random h2h intent");
            return null;
        }

        try {
            HostToHostIntent hIntent = new HostToHostIntent(new ResourceHost(src.getId()),
                    new ResourceHost(dst.getId()));
            ONOSUtil.setIntentToONOS(hIntent);
            intentStore.addIntent(hIntent.getKey(), hIntent);
            // TODO: command interface
            return hIntent;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public Intent randomPointToPointIntent() {
        Random rand = new Random();
        Set<TopoEdge> edges = graph.getAllEdges();
        if (edges.size() == 0)
            return null;

        int srcIdx = rand.nextInt(edges.size());
        int dstIdx = rand.nextInt(edges.size());

        TopoEdge src = null, dst = null;
        TopoNode srcNode = null, dstNode = null;

        int idx = 0;
        for (TopoEdge edge : edges) {
            if (idx == srcIdx) {
                src = edge;
                // Create temporary srcEdge from selected edge
                if (edge instanceof TopoHostEdge && edge.getSrcPort() == null) {
                    src = new TopoHostEdge(edge.getDstId(), edge.getSrcId(),
                            edge.getDstPort(), edge.getSrcPort());
                }

                srcNode = graph.getNode(src.getSrcId());
            }

            if (idx == dstIdx) {
                dst = edge;
                // Create temporary dstEdge from selected edge
                if (edge instanceof TopoHostEdge && edge.getDstPort() == null) {
                    dst = new TopoHostEdge(edge.getDstId(), edge.getSrcId(),
                            edge.getDstPort(), edge.getSrcPort());
                }

                dstNode = graph.getNode(dst.getDstId());
            }

            idx ++;
        }

        if (src == null || srcNode == null || dst == null || dstNode == null) {
            log.error("Cannot create random p2p intent");
            return null;
        }

        try {
            PointToPointIntent pIntent = new PointToPointIntent(
                    new ResourcePoint(srcNode.getId(), src.getSrcPort()),
                    new ResourcePoint(dstNode.getId(), dst.getDstPort())
            );
            ONOSUtil.setIntentToONOS(pIntent);
            intentStore.addIntent(pIntent.getKey(), pIntent);
            // TODO: command interface
            return pIntent;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public SinglePointToMultiPointIntent replayOne() {
        Set<TopoHost> hosts = graph.getAllHosts(true);
        if (hosts.size() < REPLAY1_REQUIRED_HOST_NUM)
            return null;

        List<TopoHost> hostList = new ArrayList<>(hosts);
        String onosVersion = ONOSUtil.getONOSVersion();

        try {
            SinglePointToMultiPointIntent s2mIntent = new SinglePointToMultiPointIntent();
            TopoEdge srcEdge = null, dstEdge = null;
            for (TopoHost host : hosts) {
                if (srcEdge == null) {
                    srcEdge = graph.getEdgeFromSrc(host.getId(), null);
                    continue;
                }

                TopoEdge tmpEdge = graph.getEdgeFromDst(host.getId(), null);
                if (!srcEdge.getDstId().equals(tmpEdge.getSrcId())) {
                    dstEdge = tmpEdge;
                    break;
                }
            }

            if (srcEdge == null || dstEdge == null)
                return null;

            //s2mIntent.setSrc(src, graph.getEdgeFromSrc(src.getId(), null));
            s2mIntent.setSrc(new ResourcePoint(srcEdge.getDstId(), srcEdge.getDstPort()));
            //s2mIntent.addDst(dst, graph.getEdgeFromDst(dst.getId(), null));
            s2mIntent.addDst(new ResourcePoint(dstEdge.getSrcId(), dstEdge.getSrcPort()));

            HttpURLConnection conn = ONOSUtil.setIntentToONOS(s2mIntent);
            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 300 ) {
                String locHeader = conn.getHeaderField("location");
                if (locHeader != null && onosVersion.equals("1.9.0")) {
                    // XXX: old version of onos doesn't support intent's "key"
                    System.out.println(locHeader);
                    String[] loc = locHeader.split("/");
                    String key = loc[loc.length - 1];
                    s2mIntent.setKey(key);
                }

                intentStore.addIntent(s2mIntent.getKey(), s2mIntent);
                return s2mIntent;
            } else {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public SinglePointToMultiPointIntent replayTwo(SinglePointToMultiPointIntent prevIntent) {
        Random rand = new Random();
        Set<TopoHost> hosts = graph.getAllHosts(true);
        if (hosts.size() < REPLAY1_REQUIRED_HOST_NUM)
            return null;

        List<TopoHost> hostList = new ArrayList<>(hosts);

        try {
            SinglePointToMultiPointIntent s2mIntent = new SinglePointToMultiPointIntent(prevIntent);
            TopoEdge srcEdge = null;
            List<TopoEdge> dstEdgeList = new ArrayList<>();
            int count = 0;
            for (TopoHost host : hosts) {
                if (srcEdge == null) {
                    srcEdge = graph.getEdgeFromSrc(host.getId(), null);
                    continue;
                }

                TopoEdge tmpEdge = graph.getEdgeFromDst(host.getId(), null);
                if (!srcEdge.getDstId().equals(tmpEdge.getSrcId())) {
                    dstEdgeList.add(tmpEdge);
                    if (++count == 2)
                        break;
                }
            }

            if (srcEdge == null || dstEdgeList.isEmpty())
                return null;

            s2mIntent.setSrc(new ResourcePoint(srcEdge.getDstId(), srcEdge.getDstPort()));
            for (TopoEdge dstEdge : dstEdgeList) {
                s2mIntent.addDst(new ResourcePoint(dstEdge.getSrcId(), dstEdge.getSrcPort()));
            }
            ONOSUtil.setIntentToONOS(s2mIntent);
            intentStore.modIntent(s2mIntent.getKey(), s2mIntent);
            return s2mIntent;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * private classes for listeners
     */
    private static class InternalTopologyListener implements TopoGraphListener {
        @Override
        public void event(TopoGraphEvent event) {
            TopoElem elem = event.getElem();

            if (elem instanceof TopoDevice) {
                TopoDevice dev = (TopoDevice) elem;
                // TODO: logging
                log.info(" [{}] Received ': {}}'\n", event.getType().toString(), dev.toString());
            }
        }
    }

    private class InternalScenarioListener implements StoreListener<ScenarioEvent> {
        boolean storeOnce = true;
        @Override
        public void event(ScenarioEvent scenarioEvent) throws EndFuzzException {
//            System.out.println("INTENT FUZZER SERVICE: " + scenarioEvent.getEventType() +
//                    (scenarioEvent.getAction() != null ?
//                            "/" + scenarioEvent.getAction().getActionCmd() : ""));

            int seq = scenarioEvent.getSeq();

            if (scenarioEvent.getEventType().equals("APPLY")) {
                FuzzAction action = scenarioEvent.getAction();

                // 1) ADD
                if (action.getActionCmd().equals("add-intent")) {
                    String actionId = action.getId();

                    FuzzActionContent content = action.getContent();
                    assert(content instanceof FuzzActionIntentContent);

                    FuzzActionIntentContent intentContent = (FuzzActionIntentContent) content;
                    log.debug(intentContent.toString());

                    JsonObject contentJson = intentContent.getContent();
                    if (contentJson.get("controller") != null &&
                            contentJson.get("controller").getAsString().equals("onos")) {
                        if (contentJson.get("id") == null) {
                            log.error("there is no ID field in content json\n");
                            scenarioStore.failAction(actionId, seq, "id is not found", true);
                            return;
                        }

                        String intentId = contentJson.get("id").getAsString();

                        // If this intent is replayed with hint, replace mac address
                        String intentStr = intentContent.getIntent();
                        if (seq == 0 && ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
                            JsonObject intentJson = TestUtil.fromJson(intentContent.getIntent());
                            if (intentJson.has("type") &&
                                    intentJson.get("type").getAsString().equals(IntentType.HostToHostIntent.toString())) {
                                String[] members = {"one", "two"};
                                for (String member : members) {
                                    if (intentJson.has("_" + member)) {
                                        // update one mac address
                                        JsonObject pointJson = intentJson.get("_" + member).getAsJsonObject();
                                        String deviceId = pointJson.get("device").getAsString();
                                        String portId = pointJson.get("port").getAsString();
                                        TopoEdge edge = graph.getEdgeFromSrc(deviceId, portId);
                                        if (edge != null) {
                                            intentJson.addProperty(member, edge.getDstId());
                                        } else {
                                            log.warn("No edge from {}:{}", deviceId, portId);
                                        }
                                    }
                                }
                                log.debug("Replace one/two fields. {} and {}",
                                        intentJson.get("one").getAsString(),
                                        intentJson.get("two").getAsString());
                                intentStr = intentJson.toString();
                            }
                        }
                        IntentInterfaceResponse response = intentInterface.addIntent(intentStr);
                        assert(response != null);

                        Intent intent = response.getIntent();

                        if (intent != null) {
                            intentStore.addIntent(intentId, seq, intent, actionId, action.isSync());

                            if (!action.isSync()) {
                                scenarioStore.finishAction(actionId, seq, !intent.isValid(), "ACCEPTED");
                            }
                        } else {
                            scenarioStore.failAction(actionId, seq, response, false);
                        }
                    }

                // 2) DELETE
                } else if (action.getActionCmd().equals("del-intent")) {
                    String actionId = action.getId();
                    FuzzActionContent content = action.getContent();
                    JsonObject contentJson = content.getContent();
                    if (contentJson.has("controller") &&
                            contentJson.get("controller").getAsString().equals("onos")) {
                        if (!contentJson.has("id")) {
                            log.error("there is no ID field in content json\n");
                            scenarioStore.failAction(actionId, seq, "id is not found");
                            return;
                        }

                        String intentId = contentJson.get("id").getAsString();
                        ONOSIntent intent = (ONOSIntent) intentStore.getIntent(intentId);
                        if (intent == null) {
                            log.error("intent {} is not found", intentId);
                            scenarioStore.failAction(actionId, seq, "intent is not found");
                            return;
                        }

                        log.info("delete intent {} by {}", intentId, actionId);

                        boolean finished = false;
                        for (int i = 0; i < CommonUtil.getRuntimeConfigIntentWaitTimeout(); i++) {
                            try {
                                HttpURLConnection conn = ONOSUtil.delIntentToONOS(intent);
                                int responseCode = conn.getResponseCode();

                                if (!(responseCode >= 200 && responseCode < 300)) {
                                    String errorMsg = "ONOS DENY REST: " + conn.getResponseMessage();
                                    log.error(errorMsg);
                                    scenarioStore.failAction(actionId, seq, errorMsg, intent.isValid());
                                } else {
                                    String removedIntent = ONOSUtil.getIntentFromONOS(intent);
                                    if (removedIntent != null) {
                                        Thread.sleep(CommonUtil.getRuntimeConfigIntentCheckIntervalMs());
                                        continue;
                                    }

                                    intentStore.delIntent(intentId, seq, actionId, action.isSync());
                                    if (!action.isSync())
                                        scenarioStore.finishAction(actionId, seq, !intent.isValid(), "ACCEPTED");
                                }

                            } catch (Exception e) {
                                e.printStackTrace();
                                scenarioStore.failAction(actionId, seq, e.getMessage());
                            }

                            finished = true;
                            break;
                        }

                        if (!finished) {
                            scenarioStore.failAction(actionId, seq, "Timeout");
                        }
                    }

                // 3) MODIFY
                } else if (action.getActionCmd().equals("mod-intent")) {
                    String actionId = action.getId();

                    FuzzActionContent content = action.getContent();
                    assert(content instanceof FuzzActionIntentContent);

                    FuzzActionIntentContent intentContent = (FuzzActionIntentContent) content;
                    log.debug(intentContent.toString());

                    JsonObject contentJson = intentContent.getContent();
                    if (contentJson.get("controller") != null &&
                            contentJson.get("controller").getAsString().equals("onos")) {
                        if (contentJson.get("id") == null) {
                            log.error("there is no ID field in content json\n");
                            scenarioStore.failAction(actionId, seq, "id is not found", true);
                            return;
                        }

                        String intentId = contentJson.get("id").getAsString();
                        ONOSIntent intent = (ONOSIntent) intentStore.getIntent(intentId);
                        if (intent == null) {
                            log.error("intent {} is not found", intentId);
                            scenarioStore.failAction(actionId, seq, "intent is not found");
                            return;
                        }

                        // If this intent is replayed with hint, replace mac address
                        String intentStr = intentContent.getIntent();
                        if (seq == 0 && ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
                            JsonObject intentJson = TestUtil.fromJson(intentContent.getIntent());
                            if (intentJson.has("type") &&
                                    intentJson.get("type").getAsString().equals(IntentType.HostToHostIntent.toString())) {
                                String[] members = {"one", "two"};
                                for (String member : members) {
                                    if (intentJson.has("_" + member)) {
                                        // update one mac address
                                        JsonObject pointJson = intentJson.get("_" + member).getAsJsonObject();
                                        String deviceId = pointJson.get("device").getAsString();
                                        String portId = pointJson.get("port").getAsString();
                                        TopoEdge edge = graph.getEdgeFromSrc(deviceId, portId);
                                        if (edge != null) {
                                            intentJson.addProperty(member, edge.getDstId());
                                        } else {
                                            log.warn("No edge from {}:{}", deviceId, portId);
                                        }
                                    }
                                }
                                log.debug("Replace one/two fields. {} and {}",
                                        intentJson.get("one").getAsString(),
                                        intentJson.get("two").getAsString());
                                intentStr = intentJson.toString();
                            }
                        }
                        IntentInterfaceResponse response = intentInterface.modIntent(intent.getKey(),
                                intent.getAppId(), intentStr);
                        assert(response != null);

                        Intent newIntent = response.getIntent();

                        if (newIntent != null) {
                            log.info("intent modification succeeds");
                            intentStore.modIntent(intentId, seq, newIntent, actionId, action.isSync());

                            if (!action.isSync()) {
                                scenarioStore.finishAction(actionId, seq, !newIntent.isValid(), "ACCEPTED");
                            }
                        } else {
                            log.error("intent modification fails");
                            scenarioStore.failAction(actionId, seq, response.getErrorMsg(), false);
                        }
                    }

                // 4) WITHDRAW
                } else if (action.getActionCmd().equals("withdraw-intent")) {
                    String actionId = action.getId();
                    FuzzActionContent content = action.getContent();
                    JsonObject contentJson = content.getContent();
                    if (contentJson.has("controller") &&
                            contentJson.get("controller").getAsString().equals("onos")) {
                        if (!contentJson.has("id")) {
                            log.error("there is no ID field in content json\n");
                            scenarioStore.failAction(actionId, seq, "id is not found");
                            return;
                        }

                        String intentId = contentJson.get("id").getAsString();
                        ONOSIntent intent = (ONOSIntent) intentStore.getIntent(intentId);
                        if (intent == null) {
                            log.error("intent {} is not found", intentId);
                            scenarioStore.failAction(actionId, seq, "intent is not found");
                            return;
                        }

                        IntentInterfaceResponse response = intentInterface.withdrawIntent(intent.getKey(), intent.getAppId());

                        if (response.isSuccess()) {
                            if (!State.REMOVED.equals(intent.getState())) {
                                intent.setState(State.WITHDRAWN);
                                if (!action.isSync()) {
                                    scenarioStore.finishAction(actionId, seq, false, "ACCEPTED");
                                } else {
                                    intentStore.updateIntent(intentId, seq, State.WITHDRAWN, Type.CHECK_REQ, actionId);
                                }
                            } else {
                                if (!action.isSync()) {
                                    scenarioStore.finishAction(actionId, seq, false, "ACCEPTED");
                                } else {
                                    intentStore.checkIntent(intentId, seq, actionId);
                                }
                            }
                        } else {
                            scenarioStore.failAction(actionId, seq, response.getErrorMsg(), false);
                        }
                    }

                // 5) PURGE
                } else if (action.getActionCmd().equals("purge-intent")) {
                    String actionId = action.getId();
                    FuzzActionContent content = action.getContent();
                    JsonObject contentJson = content.getContent();
                    if (contentJson.has("controller") &&
                            contentJson.get("controller").getAsString().equals("onos")) {
                        if (!contentJson.has("id")) {
                            log.error("there is no ID field in content json\n");
                            scenarioStore.failAction(actionId, seq, "id is not found");
                            return;
                        }

                        String intentId = contentJson.get("id").getAsString();
                        ONOSIntent intent = (ONOSIntent) intentStore.getIntent(intentId);
                        if (intent == null) {
                            log.error("intent {} is not found", intentId);
                            scenarioStore.failAction(actionId, seq, "intent is not found");
                            return;
                        }

                        IntentInterfaceResponse response = intentInterface.purgeIntent(intent.getKey(), intent.getAppId());

                        if (response.isSuccess()) {
                            if (State.WITHDRAWN.equals(intent.getState()) ||
                                    State.FAILED.equals(intent.getState())) {
                                intent.setState(State.REMOVED);
                                if (!action.isSync()) {
                                    scenarioStore.finishAction(actionId, seq, false, "ACCEPTED");
                                } else {
                                    intentStore.updateIntent(intentId, seq, State.REMOVED, Type.CHECK_REQ, actionId);
                                }
                            } else {
                                if (!action.isSync()) {
                                    scenarioStore.finishAction(actionId, seq, false, "ACCEPTED");
                                } else {
                                    intentStore.checkIntent(intentId, seq, actionId);
                                }
                            }
                        } else {
                            if (State.REMOVED.equals(intent.getState()) &&
                                    response.getErrorMsg().startsWith("Not found")) {
                                // Try to purge already-removed intent -> failed
                                scenarioStore.finishAction(actionId, seq, false, "ACCEPTED");
                            } else {
                                scenarioStore.failAction(actionId, seq, response.getErrorMsg(), false);
                            }
                        }
                    }

                // 6) CLEAR
                } else if (action.getActionCmd().equals("clear-intent")) {
                    clearIntents();
                    scenarioStore.finishAction(action.getId(), seq);

                } else if (action.getActionCmd().equals("add-rule")) {
                    log.debug("[P4] received rules: " + action.getContent().getContent());
                    String actionId = action.getId();

                    FuzzActionContent content = action.getContent();
                    assert(content instanceof FuzzActionP4TestContent);

                    FuzzActionP4TestContent ruleContent = (FuzzActionP4TestContent) content;
                    JsonObject contentJson = content.getContent();
                    if (contentJson.has("controller") &&
                            contentJson.get("controller").getAsString().equals("onos")) {

                        if (!(intentInterface instanceof ONOSAgentInterface))
                            return;

                        IntentInterfaceResponse response;
                        P4Testgen.TestCase testCaseWithRules = ruleContent.getTestCase();

                        if (CommonUtil.isRuntimeConfigApplyDiffP4Rules()) {
                            response = applyDiffRules(testCaseWithRules);
                        } else {
                            // Assume that ONOS has no rule
                            response = ((ONOSAgentInterface) intentInterface)
                                    .addRule(ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, testCaseWithRules);
                        }

                        if (!response.isSuccess()) {
                            scenarioStore.failAction(actionId, seq, response.getErrorMsg());
                        } else {
                            ruleStore.addMember(ruleContent.getId(), response.getRules(), true);
                            scenarioStore.finishAction(action.getId(), seq);
                        }
                    }
                }
            } else if (scenarioEvent.getEventType().equals("CLEAR")) {
                clearIntents();
                if (!CommonUtil.isRuntimeConfigApplyDiffP4Rules())
                    clearAllRules();
            }
        }

        private IntentInterfaceResponse applyDiffRules(P4Testgen.TestCase testCaseWithRules)
                throws EndFuzzException {
            List<Entity_Fuzz> prevEntityList = ruleStore.getAllMembers().stream()
                    .flatMap(List::stream)
                    .map(k -> Entity_Fuzz.newBuilder(k)
                            .clearOnosFlowId()
                            .clearOnosFlowStatus()
                            .clearOnosGroupId()
                            .clearOnosGroupStatus()
                            .build())
                    .collect(Collectors.toList());
            P4Testgen.TestCase.Builder diffRuleBuilder = P4Testgen.TestCase.newBuilder(testCaseWithRules).clearEntities();
            List<Entity_Fuzz> existEntityList = new LinkedList<>();

            for (Entity_Fuzz newEntity : testCaseWithRules.getEntitiesList()) {
                Entity_Fuzz foundEntity = null;
                for (Entity_Fuzz prevEntity : prevEntityList) {
                    if (prevEntity.equals(newEntity)) {
                        foundEntity = prevEntity;
                        break;
                    }
                }

                if (foundEntity == null) {
                    diffRuleBuilder.addEntities(newEntity);
                } else {
                    prevEntityList.remove(foundEntity);
                    existEntityList.add(foundEntity);
                }
            }

            /* 4. Delete exist rules first */
            removeRules(prevEntityList);
            ruleStore.clear();

            /* 5. Then, add new rules */
            IntentInterfaceResponse response = ((ONOSAgentInterface) intentInterface)
                    .addRule(ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, diffRuleBuilder.build());
            if (response.isSuccess())
                response.getRules().addAll(existEntityList);
            return response;
        }

        private void clearAllRules() throws EndFuzzException {
            List<Entity_Fuzz> ruleList = ruleStore.getAllMembers().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toList());
            removeRules(ruleList);
            ruleStore.clear();
        }

        private void removeRules(List<Entity_Fuzz> ruleList) throws EndFuzzException {
            if (!(intentInterface instanceof ONOSAgentInterface)) {
                // TODO: support other interfaces
                return;
            }

            // TODO: support multiple devices
            String devId = ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID;
            if (devId.isEmpty()) {
                return;
            }
            ONOSAgentInterface agentInterface = (ONOSAgentInterface) intentInterface;

            boolean allowModGroup = true;
            while (!ruleList.isEmpty()) {
                log.info("Delete {} rules", ruleList.size());
                agentInterface.delRule(devId,
                        TestCase.newBuilder().addAllEntities(ruleList).build());

                // Remove at once
                int numTrial = CommonUtil.getRuntimeConfigFlowWaitTimeoutSec() * 1000 /
                        CommonUtil.getRuntimeConfigFlowCheckIntervalMs();
                while (numTrial-- > 0) {
                    IntentInterfaceResponse response = agentInterface.getRule(devId,
                            TestCase.newBuilder().addAllEntities(ruleList).build());

                    if (response.isSuccess()) {
                        ruleList = response.getRules();
                        Iterator<Entity_Fuzz> it = ruleList.iterator();
                        while (it.hasNext()) {
                            Entity_Fuzz rule = it.next();
                            boolean isRemoved = true;
                            // Not removed, if rule has group with valid status.
                            if (!rule.getOnosGroupId().isEmpty() && !rule.getOnosGroupStatus().isEmpty()) {
                                isRemoved = false;
                            }

                            // Not removed, if rule has valid flow status.
                            if (!rule.getOnosFlowStatus().isEmpty()) {
                                isRemoved = false;
                            }

                            if (isRemoved)
                                it.remove();
                        }
                    } else {
                        log.warn("Cannot get rules: {}", response.getErrorMsg());
                    }

                    // Confirm all rules are deleted
                    if (ruleList.isEmpty())
                        break;

                    try {
                        Thread.sleep(CommonUtil.getRuntimeConfigFlowCheckIntervalMs());
                    } catch (InterruptedException ignore) {}
                }

                // Confirm all rules are deleted
                if (ruleList.isEmpty())
                    break;

                if (allowModGroup) {
                    /* NOTE: Print TTF_BUG2 to FuzzCommand.ttf here, since clearing is synchronous. */
                    if (FuzzCommand.foundTTFMap != null &&
                            !FuzzCommand.foundTTFMap.containsKey(ChimeraTTF.ONOS_BUG_GROUP_DEL) &&
                            FuzzCommand.startFuzzDate != null &&
                            FuzzCommand.ttfOut != null) {
                        Duration foundTTFTime = Duration.between(FuzzCommand.startFuzzDate, LocalDateTime.now());

                        FuzzCommand.ttfOut.printf("%d %d.%d\n", ChimeraTTF.ONOS_BUG_GROUP_DEL.getIdx(), foundTTFTime.getSeconds(),
                                TimeUnit.NANOSECONDS.toMillis(foundTTFTime.getNano()));
                        FuzzCommand.ttfOut.flush();
                        FuzzCommand.foundTTFMap.put(ChimeraTTF.ONOS_BUG_GROUP_DEL, foundTTFTime);
                    }

                    allowModGroup = false;
                    // Otherwise, try to modify group id
                    IntentInterfaceResponse response = agentInterface.modGroup(devId,
                            TestCase.newBuilder().addAllEntities(ruleList).build());

                    if (response.isSuccess()) {
                        // update ruleLists with modified group
                        ruleList = response.getRules();
                        log.info("Modify group for {} rules", ruleList.size());

                    } else {
                        throw new EndFuzzException("Cannot clear rules: " + response.getErrorMsg());
                    }
                } else {
                    throw new EndFuzzException("Cannot clear rules: timeout");
                }
            }
        }

        private void clearIntents() {
            // Clear all intents
            Queue<Intent> intents = new LinkedBlockingQueue<>(intentStore.getAllIntents());
            log.debug("Clear {} intents", intents.size());
            while (!intents.isEmpty()) {
                Intent intent = intents.poll();
                if (State.REMOVED.equals(intent.getState()))
                    continue;

                if (intent instanceof ONOSIntent) {
                    try {
                        log.debug("delete intent: {}", intent.toString());
                        HttpURLConnection conn = ONOSUtil.delIntentToONOS((ONOSIntent) intent);
                        int responseCode = conn.getResponseCode();

                        if (!(responseCode >= 200 && responseCode < 300)) {
                            String errorMsg = "ONOS DENY REST: " + conn.getResponseMessage();
                            log.error(errorMsg);
                        } else {
                            String removedIntent = ONOSUtil.getIntentFromONOS(intent);
                            if (removedIntent != null) {
                                log.info("intent is not removed yet");
                                intents.add(intent);
                            } else {
                                log.debug("Success to delete");
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

            intentStore.clear();
        }
    }
}
