package edu.purdue.cs.pursec.ifuzzer.store.impl;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.ActionFuzzStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.CoverageUpdateInfo;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.FuzzIntentPacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.store.api.ScenarioEvent;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreListener;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ChimeraTTF;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4VulnType;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.MaskingCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;


/**
 * Data Store for a Current Scenario (multiple actions)
 */
public class ScenarioStore {
    public static FuzzScenarioGuidance scenarioGuidance;
    public static TopologyIntentGuidance globalTopoGuidance;
    public static FuzzIntentPacketGuidance packetGuidance;
    private static final Logger log = LoggerFactory.getLogger(ScenarioStore.class);
    private final Set<StoreListener<ScenarioEvent>> listeners;
    private final Hashtable<String, FuzzAction> actionList;
    // TODO: currently applied configActions
    private final List<TopoOperation> configTopoOperations = new ArrayList<>();

    private int executeCnt = 0;
    public static LocalDateTime startTime;
    public static Duration execDuration;

    public ScenarioStore() throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        listeners = new CopyOnWriteArraySet<>();
        actionList = new Hashtable<>();
        Class scenarioClazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl."
                + ConfigConstants.CONFIG_FUZZING_SCENARIO_GUIDANCE);
        scenarioGuidance = (FuzzScenarioGuidance) scenarioClazz.getDeclaredConstructor().newInstance();
        globalTopoGuidance = new TopologyIntentGuidance();

        Class packetClazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl."
                + ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE);
        packetGuidance = (FuzzIntentPacketGuidance) packetClazz.getDeclaredConstructor().newInstance();
    }

    public void init() {
        executeCnt = 0;
        startTime = null;
    }

    public void setStartFuzzing(LocalDateTime startTime, Duration execDuration) {
        ScenarioStore.startTime = startTime;
        ScenarioStore.execDuration = execDuration;
    }

    /**
     * operations
     */
    public String execute(FuzzScenario scenario, LineReader reader) {
        try {
            log.debug("Run scenario (seq: {}): {}", executeCnt + 1,
                    scenario.toJsonObject().toString());
        } catch (IOException ignored) {}

        // [Init] clear lists
        if (!actionList.isEmpty())
            actionList.clear();

        int seq = ++executeCnt;

        // [Init] run initActions
        List<FuzzAction> initActions = scenario.getInitActions();
        int hostAddCnt = 0;
        for (FuzzAction initAction : initActions) {
            if (initAction.getActionCmd().equals("add-host")) {
                hostAddCnt++;
            } else if (initAction.getActionCmd().equals("add-link") &&
                    hostAddCnt > 0) {
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException interruptedException) {
                    interruptedException.printStackTrace();
                }
                hostAddCnt = 0;
            }

            applyAction(initAction, seq, scenario);
            waitAction(initAction.getId(), seq);
            System.out.printf("[%s %s] %s\n", scenario.getName(), initAction.getActionCmd(),
                    initAction.getErrorMsg() == null ? "Success" : initAction.getErrorMsg());
        }

        // Get all topoOperations of configActions
        List<TopoOperation> newTopoOperations = new ArrayList<>();
        for (FuzzAction configAction : scenario.getConfigActions()) {
            try {
                newTopoOperations.add(new TopoOperation(configAction));
            } catch (IllegalArgumentException ignored) {}
        }

        // If there are topoOperations in configActions, recompute applied topoOperations.
        if (!newTopoOperations.isEmpty()) {
            hostAddCnt = 0;
            List<TopoOperation> syncOperations = FuzzUtil.getDiffTopoOperations(configTopoOperations, newTopoOperations);
            if (!syncOperations.isEmpty()) {
                for (TopoOperation syncOperation : syncOperations) {
                    FuzzAction syncAction = syncOperation.toFuzzAction();
                    if (syncAction.getActionCmd().equals("add-host")) {
                        hostAddCnt++;
                    } else if (syncAction.getActionCmd().equals("add-link") &&
                            hostAddCnt > 0) {
                        try {
                            TimeUnit.SECONDS.sleep(1);
                        } catch (InterruptedException interruptedException) {
                            interruptedException.printStackTrace();
                        }
                        hostAddCnt = 0;
                    }

                    applyAction(syncAction, seq, scenario);
                    waitAction(syncAction.getId(), seq);
                    System.out.printf("[%s %s] %s\n", scenario.getName(), syncAction.getActionCmd(),
                            syncAction.getErrorMsg() == null ? "Success" : syncAction.getErrorMsg());
                }

                // Reset applied config actions
                configTopoOperations.clear();
                configTopoOperations.addAll(newTopoOperations);
            }
        }

        for (FuzzAction configAction : scenario.getConfigActions()) {
            if (!configAction.isTopoOperation()) {
                // apply intent operations in advance
                applyAction(configAction, seq, scenario);
                waitAction(configAction.getId(), seq);
                System.out.printf("[%s %s] %s\n", configAction.getId(), configAction.getActionCmd(),
                        configAction.getErrorMsg() == null ? "Success" : configAction.getErrorMsg());
                if (configAction.isError()) {
                    scenario.setError(configAction.getErrorMsg());
                    return null;
                }
            }
        }

        Stack<TopoOperation> appliedTopoOperations = new Stack<>();

        try {
            scenarioGuidance.resetCoverage();

            if ((scenario.isFuzzed() && scenarioGuidance.isContinuous()) ||
                    packetGuidance.isContinuous()) {
                // do background coverage update
                scenario.startCoverageBgWorker();
            }
        } catch (NumberFormatException | IOException e) {
            log.error(e.getMessage());
        }

        /* MAIN */
        HashMap<String, FuzzAction> storedFuzzActionsByIntentKey = new HashMap<>();
        HashMap<String, FuzzAction> failedActionsByIntentKey = new HashMap<>();
        List<String> errorIntentKeyList = new ArrayList<>();
        int i = 1, local_seq = 0;
        try {
            // 1. Execute all actions in the given scenario
            boolean cont = false;
            FuzzAction fuzzedAction = null;
            String origActionId = null;
            while (true) {
                FuzzAction action;
                boolean isFuzzedAction = false;
                // 1) Get Action
                if (fuzzedAction != null) {
                    /* FUZZED */
                    action = fuzzedAction;
                    fuzzedAction = null;
                    isFuzzedAction = true;
                } else if (scenario.isDone()) {
                    /* FINISHED */
                    break;
                } else {
                    /* NEXT */
                    action = scenario.getNextAction();
                    local_seq = 0;
                    origActionId = action.getId();
                }

                if (!action.isExecutable())
                    continue;

                // Receive input from user
                if (reader != null && !cont) {
                    while (true) {
                        String prompt = String.format("[%d] %s (Y/n/c)> ", i, action.getActionCmd());

                        String input = reader.readLine(prompt, null, (MaskingCallback) null, null).trim().toLowerCase();
                        if (input.length() == 0 || input.equals("y")) {
                            break;
                        } else if (input.equals("c")) {
                            cont = true;
                            break;
                        } else if (input.equals("n")) {
                            i++;
                            throw new EndOfFileException("done");
                        }
                    }
                }

                TopoOperation topoOperation = null;
                if (action.isTopoOperation()) {
                    topoOperation = new TopoOperation(action);
                }

                Instant startActionTime = null;
                if (ScenarioStore.recordExecTime(scenario)) {
                    startActionTime = Instant.now();
                }

                // 2) send it to proper services
                applyAction(action, seq, scenario);
                // 3) wait the result (sync) or continue action (async)
                if (action.isSync()) {
                    waitAction(action.getId(), seq);

                    if (startActionTime != null) {
                        Instant endActionTime = Instant.now();
                        action.setDurationMillis(startActionTime, endActionTime);
                        scenarioGuidance.addActionResult(action);
                    }
                    scenario.applyIntentStateCoverage(action, action.getRetObject());

                    if (!(action.getActionCmd().contains("verity-intent")) &&
                            !(action.getActionCmd().equals("del-intent"))) {
                        if (action.getRetObject() instanceof Intent) {
                            Intent retIntent = (Intent) action.getRetObject();
                            String intentId = action.getContent().getId();
                            log.debug("By action {} -> {}", action.getActionCmd(), retIntent.getState());
                            if (State.INSTALLED.equals(retIntent.getState())) {
                                // If it is mod-intent, it will overwrite previous add/mod-intent.
                                if (action.getActionCmd().equals("add-intent") ||
                                        action.getActionCmd().equals("mod-intent"))
                                    storedFuzzActionsByIntentKey.put(intentId, action);
                            } else {
                                storedFuzzActionsByIntentKey.remove(intentId);
                            }
                        }
                    }
                } else {
                    // TODO: Apply before getting return object
                    scenario.applyIntentStateCoverage(action);
                }
                i++;

                System.out.printf("[%s %s] %s\n", action.getId(), action.getActionCmd(),
                        action.getErrorMsg() != null ? action.getErrorMsg() : "Success");

                /*
                 * [Action-level Fuzzing]
                 * Normally, it stops executing scenario after the error action.
                 * While mutating actions, however, it continues action fuzzing.
                 * For the first time, fuzzer checks given scenario to decide
                 * whether to mutate actions or not (e.g., duplicated rules).
                 */
                boolean stopExecWhenError = true;
                if (scenario.isFuzzed()) {
                    ActionFuzzStatus actionFuzzStatus = scenarioGuidance.continueActionFuzzing(isFuzzedAction ? null : scenario, action);

                    if (!actionFuzzStatus.equals(ActionFuzzStatus.UNSUPPORTED)) {
                        CoverageUpdateInfo findNewPathReasons = null;
                        FuzzScenario scenarioWithMutant = scenario;
                        if (isFuzzedAction) {
                            scenarioWithMutant = FuzzScenario.copy(scenario, action);
                            scenarioWithMutant.setFuzzed(true);
                        }

                        try {
                            // When action is initial action or error, dump controller
                            boolean dumpCtrl = action.isError() || !isFuzzedAction;

                            // Optimize: dump controller if scenario
                            if (!dumpCtrl) {
                                P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(scenarioWithMutant);
                                if (testCase != null && P4Util.hasControllerImpact(testCase))
                                    dumpCtrl = true;
                            }
                            // Measure coverages in scenario (not copied scnearioWithMutant)
                            // just after executing one action.
                            findNewPathReasons = scenarioGuidance.measureCoverage(scenario, action,
                                    false, false, dumpCtrl);

                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                        // store interesting mutant into seed
                        boolean isInteresting = findNewPathReasons != null && findNewPathReasons.isUpdated();
                        if (isInteresting) {
                            // TODO: whether to store a packet or packet traces?
                            scenarioGuidance.addSeed(scenarioWithMutant, findNewPathReasons);
                            scenario.dontStoreSeed(findNewPathReasons);
                        }

                        // store files
                        if (action.isError()) {
                            // Log the whole scenario for the error fuzzed action
                            String fileName = LocalDateTime.now()
                                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
                            scenarioWithMutant.logScenario(FuzzCommand.failedPath + File.separator + fileName,
                                    action);
                            stopExecWhenError = false;

                            if (FuzzCommand.foundTTFMap != null &&
                                    startTime != null &&
                                    FuzzCommand.ttfOut != null) {
                                action.getFoundTTFSet().addAll(P4Util.afterCheckTTFFromScenario(scenarioWithMutant));
                                for (ChimeraTTF foundTTF : action.getFoundTTFSet()) {
                                    if (foundTTF.equals(ChimeraTTF.NO_BUG) || FuzzCommand.foundTTFMap.containsKey(foundTTF))
                                        continue;

                                    Duration foundTTFTime = Duration.between(startTime, LocalDateTime.now());
                                    FuzzCommand.foundTTFMap.put(foundTTF, foundTTFTime);
                                    FuzzCommand.ttfOut.printf("%d %d.%d\n", foundTTF.getIdx(), foundTTFTime.getSeconds(),
                                            TimeUnit.NANOSECONDS.toMillis(foundTTFTime.getNano()));
                                    FuzzCommand.ttfOut.flush();
                                    scenarioWithMutant.logScenario(FuzzCommand.logDir + File.separator + "bug-" + foundTTF);
                                }
                            }

                        } else if (isInteresting) {
                            // Log the whole scenario for the interesting fuzzed action
                            String fileName = LocalDateTime.now()
                                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
                            scenarioWithMutant.logScenario(FuzzCommand.interestingPath + File.separator + fileName +
                                    "-" + findNewPathReasons);
                        }

                        // increment error counts for fuzzedAction
                        if (action.isError() || !action.getP4VulnType().equals(P4VulnType.NONE)) {
                            scenarioGuidance.incErrors();
                            if (isInteresting) {
                                scenarioGuidance.incUniqueErrors();
                                // scenario should have the latest updated coverages
                                scenarioGuidance.incUniqueErrorsByCovMetrics(scenario, findNewPathReasons);
                            }
                        }

                        if (actionFuzzStatus.equals(ActionFuzzStatus.PROCESSING)) {
                            try {
                                // Get new action to run again
                                fuzzedAction = scenarioGuidance.mutateAction(action, scenario);
                                if (fuzzedAction != null) {
                                    fuzzedAction.setId(origActionId + String.format("-%03d", ++local_seq));
                                }

                            } catch (IOException e) {
                                e.printStackTrace();
                            } catch (EndFuzzException | SkipFuzzException ignore) {
                                // Stop action-level fuzzing
                            }
                        }
                    }
                }

                if (action.isError()) {
                    if (action.getActionCmd().endsWith("-verify-intent")) {

                        if (action.getActionCmd().equals("dp-verify-intent")) {
                            if (action.getContent() != null) {
                                String intentKey = action.getContent().getId();
                                errorIntentKeyList.add(intentKey);
                                failedActionsByIntentKey.put(intentKey, action);
                            }
                        }

                        // In case of multiple-intent fuzzing, test scenarios as many as possible.
                        if (!(scenarioGuidance instanceof SingleIntentGuidance)) {
                            continue;
                        }
                    }

                    if (stopExecWhenError)
                        break;
                }

                if (topoOperation != null)
                    appliedTopoOperations.push(topoOperation);
            }

            // 2. Wait until all actions are finished
            for (FuzzAction action : actionList.values()) {
                if (action.isProcessing()) {
                    waitAction(action.getId(), seq);
                }
            }

            scenario.stopCoverageBgWorker();

            try {
                scenarioGuidance.measureCoverage(scenario, null,
                        true, true, true);
            } catch (NumberFormatException | IOException e) {
                log.error(e.getMessage());
            }

        } catch (EndOfFileException ignore) {
            // do nothing...
        }

        try {
            if (reader != null) {
                while (true) {
                    String prompt = String.format("[%d] clear (y/n)> ", i);

                    String input = reader.readLine(prompt, null, (MaskingCallback) null, null).trim().toLowerCase();
                    if (input.equals("y")) {
                        break;
                    } else if (input.equals("n")) {
                        return null;
                    }
                }
            }
        } catch (EndOfFileException e) {
            return null;
        }

        Instant startActionTime = null;
        if (ScenarioStore.recordExecTime(scenario)) {
            startActionTime = Instant.now();
        }
        // 3. Clear stored intents
        clearActions(scenario.getConfigTopo() == null);
        if (startActionTime != null) {
            Instant endActionTime = Instant.now();
            scenarioGuidance.addActionResultByCmd("clear",
                    Duration.between(startActionTime, endActionTime).toMillis());
        }

        if (ConfigConstants.CONFIG_P4_PIPELINE.isEmpty()) {
            // check dp-verify failed intent
            if (ConfigConstants.CONFIG_ENABLE_TEST_EACH_ERROR_INTENT &&
                    errorIntentKeyList.size() > 0) {
                log.info("### Test single {} intent(s) among {} action(s)",
                        errorIntentKeyList.size(),
                        storedFuzzActionsByIntentKey.keySet().size());
                boolean isSingleIntentDpError = true;
                for (String errorIntentKey : errorIntentKeyList) {
                    FuzzAction action = storedFuzzActionsByIntentKey.get(errorIntentKey);
                    FuzzAction verifyAction = failedActionsByIntentKey.get(errorIntentKey);
                    if (action == null || verifyAction == null) {
                        log.warn("### No action for {}", errorIntentKey);
                        continue;
                    }

                    FuzzAction delAction = FuzzAction.delIntentAction(errorIntentKey);

                    // Apply
                    FuzzAction tmpAction = FuzzAction.change("add-intent", action);
                    tmpAction.setSync();
                    applyAction(tmpAction, seq, scenario);
                    waitAction(tmpAction.getId(), seq);
                    if (tmpAction.isError()) {
                        log.warn("### Install failed for {}", errorIntentKey);
                        isSingleIntentDpError = false;
                        applyAction(delAction, seq, scenario);
                        waitAction(delAction.getId(), seq);
                        continue;
                    }

                    // CP-Verify
                    tmpAction = FuzzAction.cpVerifyAction(errorIntentKey);
                    applyAction(tmpAction, seq, scenario);
                    waitAction(tmpAction.getId(), seq);
                    if (tmpAction.isError()) {
                        log.warn("### CP-Verify failed for {}", errorIntentKey);
                        isSingleIntentDpError = false;
                        applyAction(delAction, seq, scenario);
                        waitAction(delAction.getId(), seq);
                        continue;
                    }

                    // DP-Verify
                    tmpAction = FuzzAction.dpVerifyAction(errorIntentKey);
                    applyAction(tmpAction, seq, scenario);
                    waitAction(tmpAction.getId(), seq);
                    if (!tmpAction.isError()) {
                        log.warn("### DP-Verify succeeded for {}", errorIntentKey);
                        isSingleIntentDpError = false;
                        applyAction(delAction, seq, scenario);
                        waitAction(delAction.getId(), seq);
                        continue;
                    }

                    verifyAction.setSingleIntentDpError(true);

                    // Del-intent
                    applyAction(delAction, seq, scenario);
                    waitAction(delAction.getId(), seq);
                }

                scenario.setSingleIntentDpError(isSingleIntentDpError);
            }

            // 4. Invert topo-operations
            int invIdx = 0;
            while (!appliedTopoOperations.isEmpty()) {
                TopoOperation inv = appliedTopoOperations.pop().invert();
                FuzzAction invAction = inv.toFuzzAction(String.format("%s-clear-%03d", scenario.getName(), invIdx++));
                applyAction(invAction, seq, scenario);
                waitAction(invAction.getId(), seq);
            }

            // Clear intents again
            clearActions(false);
        }

        return null;
    }

    public String execute(FuzzScenario scenario) {
        return execute(scenario, null);
    }

    public void applyAction(FuzzAction action, int seq, FuzzScenario scenario) {
        actionList.put(action.getId() + seq, action);
        scenario.logAction(action);
        notifyListener(new ScenarioEvent("APPLY", action.getId(), seq, FuzzAction.copy(action)));
    }

    public void waitAction(String actionId, int seq) {
        if (actionId == null)
            return;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                try {
                    while (!action.isSuccess() && !action.isError())
                        action.wait();
                } catch (InterruptedException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }

    public boolean setWaitCnt(String actionId, int seq, int waitCnt) {
        if (actionId == null)
            return false;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                action.setWaitCnt(waitCnt);
            }
            return true;
        }
        return false;
    }

    public boolean setFoundTTF(String actionId, int seq, ChimeraTTF foundTTF) {
        if (actionId == null)
            return false;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                action.setFoundTTF(foundTTF);
            }
            return true;
        }
        return false;
    }

    public void finishAction(String actionId, int seq) {
        finishAction(actionId, seq, false, "", null);
    }

    public void finishAction(String actionId, int seq, String subState) {
        finishAction(actionId, seq, false, subState, null);
    }

    public void finishAction(String actionId, int seq, boolean doesRequireLogging, String subState) {
        finishAction(actionId, seq, doesRequireLogging, subState, null);
    }

    public void finishAction(String actionId, int seq, boolean doesRequireLogging, String subState, Object retObject) {
        if (actionId == null)
            return;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            boolean isFinished = false;
            synchronized (action) {
                if (action.decWaitCnt() == 0) {
                    isFinished = true;
                    if (retObject != null)
                        action.setRetObject(retObject);

                    action.setReplayLogging(doesRequireLogging);
                    action.setSubState(subState);
                    action.success();
                    action.notify();
                }
            }
            if (isFinished)
                notifyListener(new ScenarioEvent("FINISH", actionId, seq, FuzzAction.copy(action)));
        }
    }

    public void finishAction(String actionId, int seq, boolean doesRequireLogging, String subState,
                             Object retObject, ChimeraTTF foundTTF) {
        if (actionId == null)
            return;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            boolean isFinished = false;
            synchronized (action) {
                if (action.decWaitCnt() == 0) {
                    isFinished = true;
                    if (retObject != null)
                        action.setRetObject(retObject);

                    action.setReplayLogging(doesRequireLogging);
                    action.setSubState(subState);
                    action.setFoundTTF(foundTTF);
                    action.success();
                    action.notify();
                }
            }
            if (isFinished)
                notifyListener(new ScenarioEvent("FINISH", actionId, seq, FuzzAction.copy(action)));
        }
    }

    public void failAction(String actionId, int seq, String errorMsg) {
        // When action is failed, log current scenario, normally...
        failAction(actionId, seq, errorMsg, true);
    }

    public void failAction(String actionId, int seq, String errorMsg, boolean doesRequireLogging) {
        if (actionId == null)
            return;

        log.warn("[{}:{}] {}", actionId, seq, errorMsg);
        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                if (action.decWaitCnt(true) == 0) {
                    action.setReplayLogging(doesRequireLogging);
                    action.error(errorMsg);
                    action.notify();
                }
            }
        }
    }

    public void failAction(String actionId, int seq, String errorMsg, boolean doesRequireLogging, Object retObject, boolean stopFuzz) {
        if (actionId == null)
            return;

        log.warn("[{}:{}] {}", actionId, seq, errorMsg);
        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                if (action.decWaitCnt(true) == 0) {
                    action.setRetObject(retObject);
                    action.setReplayLogging(doesRequireLogging);
                    action.setStopFuzz(stopFuzz);
                    action.error(errorMsg);
                    action.notify();
                }
            }
        }
    }

    public void failAction(String actionId, int seq, String errorMsg, boolean doesRequireLogging, Object retObject) {
        if (actionId == null)
            return;

        log.warn("[{}:{}] {}", actionId, seq, errorMsg);
        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                if (action.decWaitCnt(true) == 0) {
                    action.setRetObject(retObject);
                    action.setReplayLogging(doesRequireLogging);
                    action.error(errorMsg);
                    action.notify();
                }
            }
        }
    }

    public void failAction(String actionId, int seq, IntentInterfaceResponse response, boolean doesRequireLogging) {
        if (actionId == null)
            return;

        log.warn("[{}:{}] Failed w/o errorMsg", actionId, seq);
        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                if (action.decWaitCnt(true) == 0) {
                    action.setResponse(response);
                    action.setReplayLogging(doesRequireLogging);
                    action.notify();
                }
            }
        }
    }

    public void failAction(String actionId, int seq, String errorMsg, boolean doesRequireLogging, Object retObject,
                           Set<ChimeraTTF> foundTTFSet) {

        if (actionId == null)
            return;

        log.warn("[{}:{}] {}", actionId, seq, errorMsg);
        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            synchronized (action) {
                if (action.decWaitCnt(true) == 0) {
                    action.setRetObject(retObject);
                    action.setReplayLogging(doesRequireLogging);
                    action.addAllFoundTTF(foundTTFSet);
                    action.error(errorMsg);
                    action.notify();
                }
            }
        }
    }

    public Set<ChimeraTTF> getFoundTTFs(String actionId, int seq) {
        Set<ChimeraTTF> foundTTFSet = new HashSet<>();
        if (actionId == null)
            return foundTTFSet;

        FuzzAction action = actionList.get(actionId + seq);
        if (action != null) {
            foundTTFSet.addAll(action.getFoundTTFSet());
        }
        return foundTTFSet;
    }

    public boolean isSyncAction(String actionId, int seq) {
        if (actionId == null)
            return false;

        FuzzAction action = actionList.get(actionId + seq);
        return action.isSync();
    }

    public void revertAction(FuzzAction action, int seq) {
        String actionId = action.getId();
        notifyListener(new ScenarioEvent("REVERT", actionId, seq, FuzzAction.copy(action)));
        actionList.remove(actionId + seq);
    }

    public void clearActions(boolean clearTopology) {
        // TODO: if topology is defined, skip clear
        notifyListener(new ScenarioEvent("CLEAR", clearTopology));
        actionList.clear();
    }

    public void revertAllConfigTopoOperations(FuzzScenario scenario) {
        int invIdx = 0;
        int fuzzCnt = scenario.getFuzzCnt();
        for (int i = configTopoOperations.size() - 1; i >= 0; i--) {
            TopoOperation inv = configTopoOperations.get(i).invert();
            FuzzAction invAction = inv.toFuzzAction(String.format("clear-%03d", invIdx++));
            applyAction(invAction, fuzzCnt, scenario);
            waitAction(invAction.getId(), fuzzCnt);
        }
        configTopoOperations.clear();
    }

    public boolean feedbackResult(FuzzScenario scenario) {
        if (!(scenarioGuidance instanceof SingleIntentGuidance) &&
                ConfigConstants.CONFIG_TRUNCATE_ACTIONS_AFTER_ERROR &&
                !scenario.isSingleIntentDpError()) {
            List<FuzzAction> actionList = new ArrayList<>();
            boolean isError = false;
            for (FuzzAction action : scenario.getActionList()) {
                actionList.add(action);
                if (action.isError() && !action.isSingleIntentDpError()) {
                    isError = true;
                    break;
                }
            }

            if (isError) {
                scenario.clearActionList();
                actionList.forEach(scenario::addAction);
            }
        }

        return scenarioGuidance.feedbackResult(scenario);
    }

    private static boolean recordExecTime(FuzzScenario scenario) {
        if (ConfigConstants.CONFIG_STORE_INITIAL_TESTS_IN_RESULTS)
            return true;

        // record exec time when scenario has fuzzed
        return scenario.isFuzzed();
    }

    /**
     * methods for listener
     */
    public void addListener(StoreListener listener) {
        listeners.add(listener);
    }

    private void notifyListener(ScenarioEvent event) {
        listeners.forEach(listener -> {
            try {
                listener.event(event);
            } catch (EndFuzzException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Singleton
     */
    private static class InnerScenarioStore {
        private static final ScenarioStore instance;

        static {
            try {
                instance = new ScenarioStore();
            } catch (Exception e) {
                e.printStackTrace();
                throw new ExceptionInInitializerError(e);
            }
        }
    }

    public static ScenarioStore getInstance() {
        return ScenarioStore.InnerScenarioStore.instance;
    }
}
