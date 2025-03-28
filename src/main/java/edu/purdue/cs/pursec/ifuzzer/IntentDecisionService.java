package edu.purdue.cs.pursec.ifuzzer;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.comm.impl.ONOSAgentInterface;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEventListener;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.HostToHostIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphEvent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphListener;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.store.api.*;
import edu.purdue.cs.pursec.ifuzzer.store.api.GeneralStoreEvent.GeneralEventType;
import edu.purdue.cs.pursec.ifuzzer.store.impl.RuleStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4testgen.P4Testgen;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

public class IntentDecisionService {
    private static Logger log = LoggerFactory.getLogger(IntentDecisionService.class);
    private final TopoGraph graph;
    private final RuleStore ruleStore;
    private final IntentStore intentStore;
    private final ScenarioStore scenarioStore;
    private final IntentInterface intentInterface;

    private enum RuleTestStatus {
        SUCCESS,
        PROCESSING,
        ERROR,
    }

    private class RuleTestResult {
        RuleTestStatus status;
        String errorMsg;
        List<Entity_Fuzz> errorEntities;
        boolean doesRequireLogging;

        public RuleTestResult(RuleTestStatus status) {
            this.status = status;
        }

        public RuleTestResult(String errorMsg, List<Entity_Fuzz> errorEntities, boolean doesRequireLogging) {
            this.status = RuleTestStatus.ERROR;
            this.errorMsg = errorMsg;
            this.errorEntities = errorEntities;
            this.doesRequireLogging = doesRequireLogging;
        }
    }

    public IntentDecisionService(TopoGraph graph, RuleStore ruleStore, IntentStore intentStore,
                                 ScenarioStore scenarioStore, IntentInterface intentInterface) {
        this.graph = graph;
        this.ruleStore = ruleStore;
        this.intentStore = intentStore;
        this.scenarioStore = scenarioStore;
        this.intentInterface = intentInterface;

        ruleStore.addListener(new InternalRuleListener());
        intentStore.addListener(new InternalIntentListener());
        scenarioStore.addListener(new InternalScenarioListener());
    }

    public State getExpectedStateFromIntent(Intent intent) {
        if (intent.getState() != null &&
                !intent.getState().equals(State.INSTALLED) &&
                !intent.getState().equals(State.FAILED))
            return intent.getState();

        return TestUtil.getExpectedStateFromIntent(graph, intent);
    }

    /**
     * private classes for listeners
     */
    private static class InternalTopologyListener implements TopoGraphListener {
        @Override
        public void event(TopoGraphEvent event) {
            TopoElem elem = event.getElem();

            // TODO: recheck intents
        }
    }

    private class InternalRuleListener implements StoreListener<GeneralStoreEvent<List<Entity_Fuzz>>>, Runnable {
        private Map<GeneralStoreEvent, Integer> waitingEvents = new ConcurrentHashMap<>();
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        Future future = null;
        private int curTimeCnt = 0;

        private RuleTestResult verifyRules(String ruleStoreKey, boolean isTimeout) throws IOException {
            // TODO: efficiently verify subset of rules
            List<Entity_Fuzz> sentRules = ruleStore.getMember(ruleStoreKey);

            // TODO: support getRules in REST
            assert(intentInterface instanceof ONOSAgentInterface);

            IntentInterfaceResponse response = ((ONOSAgentInterface)intentInterface).getRule(
                    ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID,
                    P4Testgen.TestCase.newBuilder().addAllEntities(sentRules).build());

            boolean changed = false;
            List<Entity_Fuzz> receivedRules = response.getRules();
            List<Entity_Fuzz> newRules = new ArrayList<>();
            List<Entity_Fuzz> failedRules = new ArrayList<>();
            StringBuilder sb = new StringBuilder();

            // Search all rules
            for (Entity_Fuzz sentRule : sentRules) {

                // Check validity
                boolean isValid = true;
                if (sentRule.getEntityCase().equals(EntityCase.TABLE_ENTRY)) {
                    isValid = (sentRule.getTableEntry().getIsValidEntry() & 1) > 0;
                }

                Entity_Fuzz foundRule = null;
                for (Entity_Fuzz receivedRule : receivedRules) {
                    if (!sentRule.getOnosFlowId().equals(receivedRule.getOnosFlowId()))
                        continue;

                    if (sentRule.getOnosGroupId().isEmpty()) {
                        foundRule = receivedRule;
                        break;
                    } else if (sentRule.getOnosGroupId().equals(receivedRule.getOnosGroupId())) {
                        foundRule = receivedRule;
                        break;
                    }
                }

                // Not found
                if (foundRule == null) {
                    sb.append(", ").append(sentRule.getOnosFlowStatus()).append("(NF)");
                    if (isValid)
                        failedRules.add(sentRule);
                    continue;
                }
                sb.append(", ").append(foundRule.getOnosFlowStatus()).append("(F/")
                        .append(foundRule.getDuration()).append(")");
                if (!foundRule.getOnosGroupId().isEmpty())
                    sb.append(", [G]").append(foundRule.getOnosGroupStatus()).append("(F)");

                boolean isRuleFailed = false;
                boolean isGroupFailed = false;
                /* FLOW RULE */
                if (foundRule.getOnosFlowStatus().equals("ADDED") &&
                        (!CommonUtil.isRuntimeConfigTTFMode() || foundRule.getDuration() > 0)) {
                    if (!isValid) {
                        isRuleFailed = true;
                    }
                } else if (isValid || !isTimeout) {
                    // If invalid rule's status is not equal to ADDED even after timeout,
                    // consider as success
                    isRuleFailed = true;
                }

                /* GROUP */
                if (!foundRule.getOnosGroupId().isEmpty()) {
                    if (foundRule.getOnosGroupStatus().equals("ADDED")) {
                        if (!isValid) {
                            isGroupFailed = true;
                        }
                    } else if (isValid || !isTimeout) {
                        // If invalid rule's status is not equal to ADDED even after timeout,
                        // consider as success
                        isGroupFailed = true;
                    }
                }

                if (isValid || !isTimeout) {
                    /* If rule should be valid, it should succeed */
                    if (isRuleFailed || isGroupFailed)
                        failedRules.add(sentRule);
                } else {
                    /* If rule should be invalid, after timeout, it fails when all entities are added */
                    if (!isRuleFailed && !isGroupFailed)
                        failedRules.add(sentRule);
                }

                if (!sentRule.getOnosFlowStatus().equals(foundRule.getOnosFlowStatus())) {
                    newRules.add(foundRule);
                    changed = true;
                } else if (!sentRule.getOnosGroupStatus().equals(foundRule.getOnosGroupStatus())) {
                    newRules.add(foundRule);
                    changed = true;
                } else {
                    // Need to add existing rule to modify the whole list
                    newRules.add(sentRule);
                }
            }

            if (changed)
                ruleStore.modMember(ruleStoreKey, newRules, true);

            log.debug("[Time {}] {}/{}{}", curTimeCnt, receivedRules.size() - failedRules.size(),
                    receivedRules.size(), sb);

            if (failedRules.size() == 0) {
                return new RuleTestResult(RuleTestStatus.SUCCESS);

            } else if (isTimeout) {
                return new RuleTestResult("Failed", failedRules, !P4Util.isKnownError(failedRules));
            }

            return new RuleTestResult(RuleTestStatus.PROCESSING);
        }

        @Override
        public void event(GeneralStoreEvent event) {
            if (event.getEventType().equals(GeneralEventType.VERIFY)) {
                log.info("VERIFY RULES!");

                assert (event.getData() instanceof ScenarioEvent);
                ScenarioEvent receivedEvent = (ScenarioEvent) event.getData();
                FuzzAction receivedAction = receivedEvent.getAction();

                FuzzActionContent actionContent = receivedAction.getContent();
                String ruleStoreKey = actionContent.getId();

                try {
                    RuleTestResult result = verifyRules(ruleStoreKey, false);
                    if (result.status.equals(RuleTestStatus.SUCCESS)) {
                        scenarioStore.finishAction(receivedAction.getId(), receivedEvent.getSeq());

                    } else if (result.status.equals(RuleTestStatus.ERROR)) {
                        scenarioStore.failAction(receivedAction.getId(), receivedEvent.getSeq(),
                                result.errorMsg, result.doesRequireLogging, null,
                                P4Util.runtimeCheckTTFFromEntities(result.errorEntities,
                                        ruleStore.getMember(ruleStoreKey)));

                    } else {
                        waitingEvents.put(event, curTimeCnt);
                        if (future == null)
                            future = executor.scheduleWithFixedDelay(this, 0,
                                    CommonUtil.getRuntimeConfigFlowCheckIntervalMs(), TimeUnit.MILLISECONDS);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    scenarioStore.failAction(receivedAction.getId(), receivedEvent.getSeq(), e.getMessage());
                }
            }
        }
        @Override
        public void run() {
            curTimeCnt ++;
            if (waitingEvents.size() == 0)
                return;

            for (GeneralStoreEvent event : waitingEvents.keySet()) {
                assert (event.getData() instanceof ScenarioEvent);
                ScenarioEvent receivedEvent = (ScenarioEvent) event.getData();
                FuzzAction receivedAction = receivedEvent.getAction();

                FuzzActionContent actionContent = receivedAction.getContent();
                String ruleStoreKey = actionContent.getId();

                int waitedTime = curTimeCnt - waitingEvents.get(event);
                log.debug("{} waited {} ms", receivedAction.getId(),
                        waitedTime * CommonUtil.getRuntimeConfigFlowCheckIntervalMs());

                boolean isTimeout = (waitedTime * CommonUtil.getRuntimeConfigFlowCheckIntervalMs()
                        >= CommonUtil.getRuntimeConfigFlowWaitTimeoutSec() * 1000);

                // check it is wrong or not.
                try {
                    RuleTestResult result = verifyRules(ruleStoreKey, isTimeout);
                    if (result.status.equals(RuleTestStatus.SUCCESS)) {
                        waitingEvents.remove(event);
                        scenarioStore.finishAction(receivedAction.getId(), receivedEvent.getSeq());

                    } else if (result.status.equals(RuleTestStatus.ERROR)) {
                        waitingEvents.remove(event);
                        scenarioStore.failAction(receivedAction.getId(), receivedEvent.getSeq(),
                                result.errorMsg, result.doesRequireLogging, null,
                                P4Util.runtimeCheckTTFFromEntities(result.errorEntities,
                                        ruleStore.getMember(ruleStoreKey)));
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                    waitingEvents.remove(event);
                    scenarioStore.failAction(receivedAction.getId(), receivedEvent.getSeq(), e.getMessage());
                }
            }
        }
    }

    private class InternalIntentListener implements IntentEventListener, Runnable {
        private Map<IntentEvent, Integer> waitingEvents = new ConcurrentHashMap<>();
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        Future future = null;
        private int curTimeCnt = 0;

        @Override
        public void event(IntentEvent event) {
            if (event.getType().equals(Type.CHECK_REQ)) {
                try {
                    // Try to get intent from ONOS and compare with given intent
                    if (checkIntentFromEvent(event, false))
                        return;

                } catch (IOException e) {
                    e.printStackTrace();
                    scenarioStore.failAction(event.getActionId(), event.getSeq(), e.getMessage());
                }

                waitingEvents.put(event, curTimeCnt);
                if (future == null)
                    future = executor.scheduleWithFixedDelay(this, 0,
                            CommonUtil.getRuntimeConfigIntentCheckIntervalMs(), TimeUnit.MILLISECONDS);
            }
        }

        /**
         * TODO:
         *  - run when the remaining intents exist
         *  - handle modified intent (check whether intent exists and content has changed)
          */
        @Override
        public void run() {
            curTimeCnt ++;
            if (waitingEvents.size() == 0)
                return;

            log.debug("[{}] # of intents: {}", curTimeCnt, waitingEvents.size());
            for (IntentEvent event : waitingEvents.keySet()) {
                int waitedTime = curTimeCnt - waitingEvents.get(event);
                log.debug("{} waited {} ms", event.getIntent().getKey(),
                        waitedTime * CommonUtil.getRuntimeConfigIntentCheckIntervalMs());

                boolean isTimeout = (waitedTime >= CommonUtil.getRuntimeConfigIntentWaitTimeout());

                // check it is wrong or not.
                try {
                    if (checkIntentFromEvent(event, isTimeout)) {
                        waitingEvents.remove(event);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    waitingEvents.remove(event);
                    scenarioStore.failAction(event.getActionId(), event.getSeq(), e.getMessage());
                }
            }
        }

        /**
         * checkIntentFromEvent(): requests intent to controller and compares it with event
         *  [UNKNOWN] return false
         *  [KNOWN]
         *      [REQ]
         *          - before timeout, it returns false.
         *          - after timeout, it returns true.
         *              - with finishAction() in FAILED-expected case
         *                (only if ConfigConstants.CONFIG_ACCEPT_INSTALLING_AS_ERROR)
         *              - with failAction() in INSTALLED-expected case
         *      [INSTALLED -> INSTALLED / FAILED -> FAILED] return true with finishAction().
         *      [INSTALLED -> FAILED / FAILED -> INSTALLED] return true with failAction().
         * @param event, timeout
         * @return
         * @throws IOException
         */

        private boolean checkIntentFromEvent(IntentEvent event, boolean isTimeout) throws IOException {
            Intent reqIntent = event.getIntent();
            int seq = event.getSeq();

            IntentInterfaceResponse response = intentInterface.getIntent(reqIntent.getKey());
            Intent intent = response.getIntent();
            if (State.REMOVED.equals(reqIntent.getState())) {
                // check whether it is removed
                if (intent == null) {
                    scenarioStore.finishAction(event.getActionId(), seq, false,
                            State.REMOVED.toString(), reqIntent);
                    return true;
                } else if (!isTimeout) {
                    return false;
                } else {
                    // timeout
                    intentStore.updateIntent(event.getKey(), seq, intent.getState(), Type.CHECK_FAILED, event.getActionId());
                    scenarioStore.failAction(event.getActionId(), seq, "wrong state: " + intent.getState(),
                            true, intent);
                    return true;
                }
            }

            // Fail, if intent is not found except purge/remove requests
            if (intent == null) {
                log.warn("{} is not found in ONOS: {}", reqIntent.getKey(), response.getErrorMsg());

                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout");

                return isTimeout;
            } else if (response.getErrorMsg() != null) {
                log.warn("error while getting intent: {}", response.getErrorMsg());

                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout");

                return isTimeout;
            }

            State givenState = intent.getState();
            if (givenState == null) {
                log.warn("Unknown state");
                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout: unknown state",
                            true, intent);
                return isTimeout;
            }

            State expectedState = getExpectedStateFromIntent(reqIntent);
            log.debug("[Intent Found] expected {} vs given {}",
                    expectedState.toString(), givenState.toString());

            // Req intent == Given intent
            if (reqIntent.equalsConfig(intent)) {
                if (expectedState.equals(givenState)) {
                    /* Success: given == expected */
                    intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECKED, event.getActionId());
                    scenarioStore.finishAction(event.getActionId(), seq, false,
                            expectedState.toString(), intent);
                    return true;

                } else if (isTimeout && ConfigConstants.CONFIG_ACCEPT_INSTALLING_AS_ERROR &&
                        expectedState.equals(State.FAILED) && givenState.equals(State.REQ)) {
                    if (intent instanceof HostToHostIntent) {
                        HostToHostIntent h2hIntent = (HostToHostIntent)intent;
                        if (h2hIntent.getSrc().getHostId().toLowerCase()
                                .equals(h2hIntent.getDst().getHostId().toLowerCase())) {
                            /* BUG4 */
                            intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECK_FAILED, event.getActionId());
                            scenarioStore.failAction(event.getActionId(), seq, "BUG4/wrong state: " + givenState,
                                    true, intent, ConfigConstants.STOPFUZZ_BUG4);
                            return true;
                        }
                    }

                    /* Success: REQ as FAILED */
                    intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECKED, event.getActionId());
                    scenarioStore.finishAction(event.getActionId(), seq, false, expectedState.toString(), intent);
                    return true;
                }
            }

            if (isTimeout) {
                /* TIMEOUT -> Failed */
                intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECK_FAILED, event.getActionId());
                scenarioStore.failAction(event.getActionId(), seq, "wrong state: " + givenState,
                        true, intent);
                return true;
            }

            /* Wait when the state is updated */
            log.warn("{} waits {} (cur: {})", intent.getKey(), reqIntent.toString(), intent.toString());
            return false;
        }
    }

    private class InternalScenarioListener implements StoreListener<ScenarioEvent> {
        @Override
        public void event(ScenarioEvent scenarioEvent) {
            if (scenarioEvent.getEventType().equals("APPLY")) {
                FuzzAction action = scenarioEvent.getAction();
                if (action.getActionCmd().equals("cp-verify-intent")) {
                    JsonObject content = action.getContent().getContent();
                    // TODO: error
                    if (!content.has("intentId"))
                        return;

                    intentStore.checkIntent(content.get("intentId").getAsString(),
                            scenarioEvent.getSeq(), action.getId());
                } else if (action.getActionCmd().equals("cp-verify-rule")) {
                    log.debug("[P4] verify rule: " + action.getContent().getId());
                    ruleStore.notifyListener(action.getContent().getId(),
                            GeneralEventType.VERIFY, scenarioEvent);
                }
            }
        }
    }
}
