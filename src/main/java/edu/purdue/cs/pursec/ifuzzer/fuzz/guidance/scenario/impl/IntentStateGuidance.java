package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl;

import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.FuzzIntentScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.ScenarioGuidanceUtil;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.IntentStateGuidanceConfigs;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import me.tongfei.progressbar.ProgressBar;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.util.*;

public class IntentStateGuidance extends FuzzIntentScenarioGuidance {
    private static final int ADD_INTENT_OPERATION = 0;
    private static final int MOD_INTENT_OPERATION = 1;
    private static final int WITHDRAW_INTENT_OPERATION = 2;
    private static final int PURGE_INTENT_OPERATION = 3;
    private static final int CHANGE_TOPO_OPERATION = 4;

    private static final Random rand = new Random();
    private static Logger log = LoggerFactory.getLogger(IntentStateGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    private static final IntentStore configIntentStore = IntentStore.getConfigInstance();
    FuzzIntentGuidance intentGuidance;
    TopologyIntentGuidance topologyIntentGuidance;
    JavaCodeCoverage codeCoverage;
    Map<String, DeviceCodeCoverage> deviceCodeCovMap;
    CodeCoverage totalDevCodeCov;
    Map<String, Integer> prevDeviceHitCount;
    List<FuzzScenario> seedScenarios;
    private int prevStateHistoryCnt, prevStateChangeCnt;
    private int curSeedIdx, numCycles;
    private int numErrors;
    private int numMultiUnigueErrors[];
    List<JavaCodeCoverage> uniqueErrorCtrlCovList;
    List<DeviceCodeCoverage> uniqueErrorDevCovList;
    Stack<TopoOperation> appliedTopoOperations;
    Map<Integer, Set<ByteBuffer>> stateCoverage;
    private boolean hasSingleIntentDpError;
    IntentStateCoverage globalIntentStateCoverage;
    CoverageGuidance ccg;
    private Map<Integer, Integer> responseMap;

    public IntentStateGuidance()  throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl."
                + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
        topologyIntentGuidance = new TopologyIntentGuidance();
    }

    @Override
    public void init(Object o, String resultDirPath) throws IOException, InterruptedException {
        super.init(o, resultDirPath);
        responseMap = new HashMap<>();
        ccg = new CoverageGuidance();
        globalIntentStateCoverage = new IntentStateCoverage();
        seedScenarios = new LinkedList<>();
        codeCoverage = new JavaCodeCoverage();
        deviceCodeCovMap = new HashMap<>();
        totalDevCodeCov = new CodeCoverage();
        prevDeviceHitCount = new HashMap<>();
        appliedTopoOperations = new Stack<>();
        stateCoverage = new HashMap<>();
        curSeedIdx = -1;
        numCycles = numErrors = prevStateHistoryCnt = prevStateChangeCnt = 0;
        numMultiUnigueErrors = new int[3];
        uniqueErrorCtrlCovList = new ArrayList<>();
        uniqueErrorDevCovList = new ArrayList<>();

        // object will be ConfigTopoGraph
        topologyIntentGuidance.init(o);
        intentGuidance.init(o);
    }

    @Override
    public boolean stop() {
        super.stop();
        return topologyIntentGuidance.stop();
    }

    private List<TopoOperation> getTopoOperationFromFuzzAction(List<FuzzAction> fuzzActions) throws IOException {
        List<TopoOperation> topoOperations = new ArrayList<>();

        for (FuzzAction action : fuzzActions) {
            if (action.getActionCmd().endsWith("link") ||
                    action.getActionCmd().endsWith("device") ||
                    action.getActionCmd().endsWith("host")) {
                topoOperations.add(new TopoOperation(action));
            }
        }

        return topoOperations;
    }

    private FuzzScenario getInvertScenario(FuzzScenario scenario) throws IOException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);

        newScenario.clearActionList();
        for (FuzzAction action : scenario.getActionList()) {
            if (action.getActionCmd().endsWith("link") ||
                    action.getActionCmd().endsWith("device") ||
                    action.getActionCmd().endsWith("host")) {
                TopoOperation operation = new TopoOperation(action);
                FuzzAction configAction = operation.toFuzzAction(action.getId() + "-inv");
                configAction.setSync();
                newScenario.addConfigAction(configAction);
                newScenario.addAction(operation.invert().toFuzzAction(action.getId()));
            } else {
                newScenario.addAction(FuzzAction.copy(action));
            }
        }

        return newScenario;
    }

    private boolean applyFuzzActionIntoConfig(FuzzAction fuzzAction) {
        if (fuzzAction == null)
            return false;

        if (fuzzAction.isTopoOperation()) {
            TopoOperation topoOperation = new TopoOperation(fuzzAction);
            configTopoGraph.applyTopoOperation(topoOperation);
            appliedTopoOperations.push(topoOperation);

            List<Intent> workingIntents = new ArrayList<>();
            workingIntents.addAll(configIntentStore.getIntentsByState(State.INSTALLED).values());
            workingIntents.addAll(configIntentStore.getIntentsByState(State.FAILED).values());

            int installed = 0;
            for (Intent intent : workingIntents) {
                if (TestUtil.getExpectedStateFromIntent(configTopoGraph, intent).equals(State.INSTALLED))
                    installed ++;
            }

            if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                    installed > ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                // the number of installed intents exceeds the limit
                return false;
            }

            configIntentStore.recomputeIntents(configTopoGraph, null);
            topologyIntentGuidance.resetMatrix();
            return true;

        } else if (fuzzAction.getActionCmd().equals("add-intent")) {
            String targetId = fuzzAction.getContent().getId();
            FuzzActionIntentContent actionIntentContent = (FuzzActionIntentContent)fuzzAction.getContent();
            try {
                Intent randomIntent = ONOSUtil.getIntentFromJson(actionIntentContent.getIntent());
                State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                if (randomIntentState.equals(State.INSTALLED)) {
                    if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                            configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                    ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                        // do not generate two installed intent at the same time
                        log.debug("cannot add intent due to limit number of installed intents");
                        return false;
                    }
                }
                randomIntent.setState(randomIntentState);
                configIntentStore.addIntent(targetId, randomIntent);

            } catch (Exception ignored) {}
            return true;

        } else if (fuzzAction.getActionCmd().equals("mod-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent == null) {
                log.error("mod-intent cannot find intent by id {}", targetId);
                return false;
            }

            FuzzActionIntentContent actionIntentContent = (FuzzActionIntentContent)fuzzAction.getContent();
            try {
                Intent randomIntent = ONOSUtil.getIntentFromJson(actionIntentContent.getIntent());
                State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                if (!targetIntent.getState().equals(State.INSTALLED) &&
                        randomIntentState.equals(State.INSTALLED)) {
                    if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                            configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                    ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                        // do not generate two installed intent at the same time
                        log.debug("cannot mod intent due to limit number of installed intents");
                        return false;
                    }
                }
                randomIntent.setState(randomIntentState);
                configIntentStore.modIntent(targetId, randomIntent);

            } catch (Exception ignored) {}
            return true;

        } else if (fuzzAction.getActionCmd().equals("withdraw-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent != null && !targetIntent.getState().equals(State.REMOVED)) {
                targetIntent.setState(State.WITHDRAWN);
            }
            return true;

        } else if (fuzzAction.getActionCmd().equals("purge-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent != null && targetIntent.getState().equals(State.WITHDRAWN)) {
                targetIntent.setState(State.REMOVED);
            }
            return true;
        }

        /* unknown action */
        log.error("unknown command: {}", fuzzAction.getActionCmd());
        return false;
    }

    private int getRandOperationFromIntentId(String intentId, FuzzAction prevAction) {
        // No intent
        if (intentId == null)
            return ADD_INTENT_OPERATION;

        Intent intent = configIntentStore.getIntent(intentId);
        if (intent == null)
            return ADD_INTENT_OPERATION;

        // If prevAction was device-related action, give one more chance
        if (prevAction != null && prevAction.getActionCmd().endsWith("-device")) {
            return CHANGE_TOPO_OPERATION;
        }

        // Expected, Expected / Penalty, Number of intent / Overhead
        // => Expected * Overhead * Penalty, Expected * Overhead, Number of intent * Penalty
        // e.g.) 8, 8, 4, 4, 6 (total: 30)
        // => [0, 7][8, 15][16, 19][20, 23][24, 29]
        int[] prob = new int[5];
        if (IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD > 0) {
            prob[ADD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                    IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD *
                    IntentStateGuidanceConfigs.CONFIG_WEIGHT_ADD_INTENT;                    // fixed
            prob[MOD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                    IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // fixed
            prob[WITHDRAW_INTENT_OPERATION] = (State.WITHDRAWN.equals(intent.getState()) ? 1 : IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY) *
                    IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // dynamic
            prob[PURGE_INTENT_OPERATION] = ((State.FAILED.equals(intent.getState()) || State.WITHDRAWN.equals(intent.getState())) ?
                    IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY : 1) *
                    IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // dynamic
            prob[CHANGE_TOPO_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                    (IntentStateGuidanceConfigs.CONFIG_IS_TOPO_CHANGE_RELATIVE_TO_INTENTS ?
                            configIntentStore.getAllAliveIntents().size() : 1);

            int sum = 0;
            for (int i = 0; i < 5; i++) {
                sum += prob[i];
            }

            int target = rand.nextInt(sum);
            for (int i = 0; i < 5; i++) {
                if (target < prob[i])
                    return i;
                target -= prob[i];
            }
        } else {
            /* NO TOPO OPERATION! */
            prob[ADD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                    IntentStateGuidanceConfigs.CONFIG_WEIGHT_ADD_INTENT;                    // fixed
            prob[MOD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY;       // fixed
            prob[WITHDRAW_INTENT_OPERATION] = State.WITHDRAWN.equals(intent.getState()) ? 1 :
                    IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY; // dynamic
            prob[PURGE_INTENT_OPERATION] = (State.FAILED.equals(intent.getState()) || State.WITHDRAWN.equals(intent.getState())) ?
                    IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY : 1;       // dynamic

            int sum = 0;
            for (int i = 0; i < 4; i++) {
                sum += prob[i];
            }

            int target = rand.nextInt(sum);
            for (int i = 0; i < 4; i++) {
                if (target < prob[i])
                    return i;
                target -= prob[i];
            }
        }

        // unreachable...
        log.error("!!! fail to get operation !!!");
        return -1;
    }

    private int getNumAppendOperation(int numPrevActions, int numRemoval) {
        /*
         * If numPrevActions is too large comparing to seed, slowly append operations.
         * Eq: seed = (x > 5) ^ (numPrevActions - 1), since first action should be add-intent
         *     Also, even if the same operation, it can generate different state transitions.
         *     To simplify, we use (seed >> numPrevActions)
         * e.g) 25 seeds, prevActions = 3, should generate. (25 >> 3) == 3
         *      125 seeds, prevActions = 10, should decrease. (125 >> 10) == 0
         *      625 seeds, prevActions = 8, should generate. (625 >> 8) == 2
         * v (>= 1): velocity of append operations, which decides whether it replaces or appends.
         *    (seed >> (prevActions - v) == 0)
         *    If v is high, it appends more and more.
         *    Otherwise, it appends slowly.
         * e.g.) v = 10, 125 seeds
         *       prevActions <= 10, it always generates more operations.
         *       prevActions = 20, decrease.
         */
        int v = IntentStateGuidanceConfigs.CONFIG_VELOCITY_OF_APPEND;
        if ((seedScenarios.size() >> Integer.max(0, numPrevActions - v)) > 0) {
            // 1) append more
            return (1 + rand.nextInt(Integer.max(1,
                    IntentStateGuidanceConfigs.CONFIG_MAX_NUM_APPEND_OPERATIONS)));
        } else if (numRemoval == 0) {
            // 2) append one operation at least
            return 1;
        } else {
            // 3) append or not
            return rand.nextInt(1);
        }
    }

    @Override
    public @Nonnull CoverageUpdateInfo measureCoverage(FuzzScenario fuzzScenario, FuzzAction fuzzAction,
                                                       boolean isReset, boolean isEnd, boolean dumpCtrl)
            throws NumberFormatException, IOException {
        // Just simply measure coverage
        CoverageUpdateInfo reason = super.measureCoverage(fuzzScenario, fuzzAction, isReset, isEnd, dumpCtrl);

        if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty() && !CommonUtil.isRuntimeConfigTestGenMode()) {
            List<DeviceCodeCoverage> coverages = P4Util.getTraceBits(isReset);
            log.info("Coverage of {} device(s) is measured", coverages.size());

            CoverageUpdateInfo devReason = fuzzScenario.applyDeviceCodeCoverages(coverages);
            reason.merge(devReason);
        }

        return reason;
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {
        return getRandomScenario();
    }

    @Override
    public FuzzScenario getRandomScenario()
            throws IOException, JsonSyntaxException, EndFuzzException {
        if (seedScenarios.size() == 0)
            return null;

        curSeedIdx = (curSeedIdx + 1) % seedScenarios.size();
        if (curSeedIdx == 0)
            numCycles++;
        FuzzScenario seedScenario = seedScenarios.get(curSeedIdx);
        FuzzScenario newScenario = FuzzScenario.copy(seedScenario);
        newScenario.setFuzzCnt(seedScenario.getFuzzCnt());

        // TODO: implement mutation-based fuzzing: move action to configAction
        newScenario.clearConfigActions();
        configIntentStore.clear();

//        for (FuzzAction configAction : newScenario.getConfigActions()) {
//            if (configAction.isTopoOperation()) {
//                configTopoGraph.applyTopoOperation(new TopoOperation(configAction));
//            } else if (configAction.getActionCmd().equals("add-intent")) {
//                configIntentStore.addIntent(configAction.getContent().getContent());
//            }
//        }

        List<FuzzAction> prevActions = new ArrayList<>();
        boolean truncated = false;
        for (FuzzAction action : newScenario.getActionList()) {
            if (action.getActionCmd().contains("verify-intent")) {
                if (ConfigConstants.CONFIG_DP_VERIFY_WITH_DELETION)
                    break;
                else
                    continue;
            }

            if (action.isError() && ConfigConstants.CONFIG_TRUNCATE_ACTIONS_AFTER_ERROR) {
                truncated = true;
                break;
            }

            prevActions.add(action);
        }

        /*
         * NOTE: The number of operations is highly related to intent-state transition.
         */

        int numPrevActions = prevActions.size();
        List<FuzzAction> newRandomActions = new ArrayList<>();
        TopoOperation prevTopoOperation = null;
        int numRemoval = rand.nextInt(IntentStateGuidanceConfigs.CONFIG_MAX_NUM_REMOVE_OPERATIONS +
                (truncated ? 0 : 1));
        for (int i = 0; i < prevActions.size() - numRemoval; i++) {
            FuzzAction prevAction = prevActions.get(i);
            applyFuzzActionIntoConfig(prevAction);      // what if scenario violates config?
            newRandomActions.add(prevAction);
            if (prevAction.isTopoOperation()) {
                prevTopoOperation = new TopoOperation(prevAction);
            } else {
                prevTopoOperation = null;
            }
        }
        topologyIntentGuidance.resetMatrix();

        int actionNum = 0;
        int numActions = getNumAppendOperation(numPrevActions, numRemoval);

        FuzzAction prevAction = null;
        for (int i = 0; i < numActions; i++) {
            // purely generate random action.
            String actionId = String.format("%s-rand-%03d-%03d", newScenario.getName(),
                    newScenario.getFuzzCnt() + 1, ++actionNum);
            FuzzAction newAction = new FuzzAction(actionId);

            Intent targetIntent;
            String randomIntentStr;
            FuzzActionContent newContent;

            while (true) {
                // Get random alive intent
                String targetId = configIntentStore.getKeyOfRandomIntent(rand, true);
                int nextOperation = getRandOperationFromIntentId(targetId, prevAction);

                switch (nextOperation) {
                    case ADD_INTENT_OPERATION:
                        // add-intent
                        randomIntentStr = intentGuidance.getRandomIntentJson(null);
                        newContent = new FuzzActionIntentContent(ONOSUtil.createNewContentJson(), randomIntentStr);
                        newContent.setNewId();
                        try {
                            Intent randomIntent = ONOSUtil.getIntentFromJson(randomIntentStr);
                            State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                            if (randomIntentState.equals(State.INSTALLED)) {
                                if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                        configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                                ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                    // do not generate two installed intent at the same time
                                    continue;
                                }
                            }
                            randomIntent.setState(randomIntentState);
                            configIntentStore.addIntent(newContent.getId(), randomIntent);

                        } catch (Exception ignored) {}

                        newAction.setContent(newContent);
                        newAction.setActionCmd("add-intent");
                        newAction.setSync();
                        break;

                    case MOD_INTENT_OPERATION:
                        // mod-intent
                        targetIntent = configIntentStore.getIntent(targetId);

                        randomIntentStr = intentGuidance.getRandomIntentJson(null);
                        newContent = new FuzzActionIntentContent(ONOSUtil.createNewContentJson(), randomIntentStr);
                        newContent.setId(targetId);
                        try {
                            Intent randomIntent = ONOSUtil.getIntentFromJson(randomIntentStr);
                            State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                            if (!targetIntent.getState().equals(State.INSTALLED) &&
                                    randomIntentState.equals(State.INSTALLED)) {
                                if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                        configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                                ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                    // do not generate two installed intent at the same time
                                    continue;
                                }
                            }
                            randomIntent.setState(randomIntentState);
                            configIntentStore.modIntent(targetId, randomIntent);

                        } catch (Exception ignored) {}

                        newAction.setContent(newContent);
                        newAction.setActionCmd("mod-intent");
                        newAction.setSync();
                        break;

                    case WITHDRAW_INTENT_OPERATION:
                        // withdraw-intent
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (!targetIntent.getState().equals(State.REMOVED)) {
                            targetIntent.setState(State.WITHDRAWN);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("withdraw-intent");
                        newAction.setSync();

                        break;

                    case PURGE_INTENT_OPERATION:
                        // purge-intent
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (targetIntent.getState().equals(State.WITHDRAWN)) {
                            targetIntent.setState(State.REMOVED);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("purge-intent");
                        newAction.setSync();

                        break;

                    case CHANGE_TOPO_OPERATION:
                        // topology operation
                        // Get random operations from current matrix
                        List<Intent> workingIntents = new ArrayList<>();
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.INSTALLED).values());
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.FAILED).values());

                        TopoOperation topoOperation;
                        while (true) {
                            topoOperation = topologyIntentGuidance.getRandomTopoOperationFromCurMatrix(prevTopoOperation);
                            configTopoGraph.applyTopoOperation(topoOperation);

                            int installed = 0;
                            for (Intent intent : workingIntents) {
                                if (TestUtil.getExpectedStateFromIntent(configTopoGraph, intent).equals(State.INSTALLED))
                                    installed ++;
                            }

                            if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                    installed > ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                // the number of installed intents exceeds the limit
                                configTopoGraph.applyTopoOperation(topoOperation.invert());
                                continue;
                            }

                            // apply topo-operation
                            configIntentStore.recomputeIntents(configTopoGraph, null);
                            break;
                        }
                        prevTopoOperation = topoOperation;
                        appliedTopoOperations.push(topoOperation);
                        topologyIntentGuidance.resetMatrix();
                        newAction = topoOperation.toFuzzAction(actionId);
                        newAction.setSync();
                        break;

                    default:
                        break;
                }

                // successfully generate operation
                break;
            }

            newRandomActions.add(newAction);
            prevAction = newAction;

            if (!newAction.isTopoOperation())
                prevTopoOperation = null;
        }

        // Move newRandomActions to newScenario
        ScenarioGuidanceUtil.setNewActions(newScenario, newRandomActions, configIntentStore);

        // revert configTopoGraph
        while (!appliedTopoOperations.isEmpty()) {
            configTopoGraph.applyTopoOperation(appliedTopoOperations.pop().invert());
        }

        return newScenario;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        super.feedbackResult(fuzzScenario);

        boolean[] isMultiUnique = new boolean[2];
        boolean isError = fuzzScenario.isError();
        boolean isSingleIntentDpError = fuzzScenario.isSingleIntentDpError();

        if (isError)
            numErrors ++;

        // update code coverage
        codeCoverage.updateCoverage(fuzzScenario.getCodeCoverage());
        int curHitCount = codeCoverage.getHitCount();

        // update dev code coverage
        List<DeviceCodeCoverage> deviceCodeCoverages = fuzzScenario.getDeviceCodeCoverages();
        DeviceCodeCoverage scenarioDevCoverage = null;
        if (deviceCodeCoverages != null) {
            for (DeviceCodeCoverage deviceCodeCoverage : deviceCodeCoverages) {
                // 1) Update local var (scenarioDevCoverage)
                if (scenarioDevCoverage == null)
                    scenarioDevCoverage = deviceCodeCoverage.deepCopy();
                else
                    scenarioDevCoverage.updateCoverage(deviceCodeCoverage);

                // 2) Update total coverage
                totalDevCodeCov.updateCoverage(deviceCodeCoverage);
                String deviceId = deviceCodeCoverage.getDeviceId();
                String subKey = deviceId.substring("device:".length());

                // 3) Put coverage map
                if (deviceCodeCovMap.containsKey(deviceId)) {
                    deviceCodeCovMap.get(deviceId).updateCoverage(deviceCodeCoverage);
                } else {
                    deviceCodeCovMap.put(deviceId, new DeviceCodeCoverage(deviceCodeCoverage));
                }

                // 4) Put hit count
                int devCurHitCount = deviceCodeCovMap.get(deviceId).getHitCount();
                int devPrevHitCount = prevDeviceHitCount.computeIfAbsent(deviceId, k -> 0);
                if (devPrevHitCount < devCurHitCount) {
//                reason.hasUpdated("DC" + devKey, deviceCodeCoverage);
                    prevDeviceHitCount.put(deviceId, devCurHitCount);
                    log.info("#[DEV:{}]# Add new matrix {} -> {} into seeds ##",
                            subKey, devPrevHitCount, devCurHitCount);
                }
            }
        }

        // update state coverage
        IntentStateCoverage coverage = fuzzScenario.getIntentStateCoverage();
        globalIntentStateCoverage.updateCoverage(coverage);
        int curStateChangeCnt = coverage.getIntentStateChangeCnt();
        boolean newValue = stateCoverage.computeIfAbsent(curStateChangeCnt, k -> new HashSet<>())
                .add(ByteBuffer.wrap(coverage.toByteArray()).asReadOnlyBuffer());

        if (curStateChangeCnt > prevStateChangeCnt) {
            if (IntentStateGuidanceConfigs.CONFIG_ENBALE_ISTG) {
                seedScenarios.add(fuzzScenario);
            }

            log.info("## [StateChangeCnt] {} -> {} Add scenario into seeds: {} | cycle {} ##",
                    prevStateChangeCnt, curStateChangeCnt,
                    seedScenarios.size(), numCycles);
            prevStateChangeCnt = curStateChangeCnt;
            isMultiUnique[1] = true;

        } else if (newValue) {
            if (IntentStateGuidanceConfigs.CONFIG_ENBALE_ISTG)
                seedScenarios.add(fuzzScenario);

            log.info("## [StateTransition] {} into seeds: {} | cycle {} ##",
                    coverage.toHexString(),
                    seedScenarios.size(), numCycles);
            try {
                log.debug("[Interpret] {}", fuzzScenario.toJsonObject().toString());
                log.debug(coverage.toString());
            } catch (Exception ignored) {
            }
            // log.debug(IntentStateCoverage.toStringFromByteArray(coverage.toByteArray()));
            isMultiUnique[1] = true;
        }

        if (ccg.isUniqueCrash(fuzzScenario.getCodeCoverage()) > 0) {
            if (IntentStateGuidanceConfigs.CONFIG_ENABLE_CCG) {
                // Guidance finds new coverage path
                seedScenarios.add(fuzzScenario);
            }

            log.info("## [CodeCoverage] {} into seeds: {} | cycle {} ##",
                    curHitCount, seedScenarios.size(), numCycles);
            isMultiUnique[0] = true;
        }

        // log once for single-intent-dp-error
        if (hasSingleIntentDpError && isSingleIntentDpError) {
            isMultiUnique[0] = false;
            isMultiUnique[1] = false;
        }

        if (isError) {
            boolean isUnique = false;
            for (int i = 0; i < 2; i++) {
                if (isMultiUnique[i]) {
                    isUnique = true;
                    numMultiUnigueErrors[i] ++;

                    // Store covMap if it finds new code coverage
                    if (i == 0) {
                        uniqueErrorCtrlCovList.add(fuzzScenario.getCodeCoverage().deepCopy());
                        uniqueErrorDevCovList.add(scenarioDevCoverage);
                    }
                }
            }

            if (isUnique) {
                log.info("## {}: interesting bug", fuzzScenario.getName());
                fuzzScenario.setUniqueError();
                numMultiUnigueErrors[2]++;
            }
        }

        if (isSingleIntentDpError) {
            hasSingleIntentDpError = true;
        }

        intentGuidance.feedbackResult(fuzzScenario);
        topologyIntentGuidance.feedbackResult(fuzzScenario);

        return true;
    }

    private FuzzAction getRandomTopoAction(FuzzAction configAction) {
        if (configAction.getActionCmd().endsWith("link") ||
                configAction.getActionCmd().endsWith("device") ||
                configAction.getActionCmd().endsWith("host")) {
            FuzzAction newAction = topologyIntentGuidance.getRandomTopoOperation().toFuzzAction(configAction.getId());
            newAction.setSync();
            return newAction;
        }

        return FuzzAction.copy(configAction);
    }

    @Override
    public FuzzAction getRandomAction(FuzzAction action) throws IOException, EndFuzzException {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);

        FuzzActionContent seedContent = action.getSeedContent();
        if (seedContent instanceof FuzzActionIntentContent) {

            // copy content from the seed
            FuzzActionIntentContent newContent = (FuzzActionIntentContent) seedContent.deepCopy();

            // get intent from the content
            String intent = newContent.getIntent();

            // generate random withdraw request..!
            String randomIntent = intentGuidance.getRandomIntentJson(intent);

            // set intent
            newContent.setIntent(randomIntent);

            // update content
            newAction.setContent(newContent);
        }

        return newAction;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        return topologyIntentGuidance.doesRequireLogging(scenario);
    }

    @Override
    public String getStatsHeader() {
        return JavaCodeCoverage.getStatsHeader()
                + ", " + IntentStateCoverage.getStatsHeader()
                + ", dev-cov avg/max"
                + ", num ops, max IST cnt, IST entries, seed, cycles, errors, uniqueErrors (CCG, ISTG, ALL)";
    }

    @Override
    public String getStatsString() {
        // code-cov stats
        StringBuilder builder = new StringBuilder(codeCoverage.getStatsString());

        // intent-cov stats
        builder.append(", ").append(globalIntentStateCoverage.getStatsString());

        // dev-cov stats
        OptionalDouble devCovAvg = prevDeviceHitCount.values().stream()
                .mapToInt(Integer::intValue).average();
        Optional<Integer> devCovMax = prevDeviceHitCount.values().stream()
                .max(Comparator.naturalOrder());
        devCovAvg.ifPresent(val -> builder.append(", ").append(val));
        devCovMax.ifPresent(val -> builder.append(", ").append(val));
        builder.append(", ").append(totalDevCodeCov.getHitCount());

        // guidance stats
        builder.append(", ").append(prevStateChangeCnt);
        builder.append(", ").append(stateCoverage.values().stream().mapToInt(Set::size).sum());
        builder.append(", ").append(seedScenarios.size());
        builder.append(", ").append(numCycles);
        builder.append(", ").append(numErrors);
        for (int numMultiUnigueError : numMultiUnigueErrors)
            builder.append(", ").append(numMultiUnigueError);

        return builder.toString();
    }

    @Override
    public void storeMetadata(String logDir) {

        if (!CommonUtil.isRuntimeConfigTestGenMode()) {
            try {
                File covFile = new File(logDir + File.separator + ONOSUtil.ONOSCovOutputFile);
                PrintStream covOut = new PrintStream(covFile);
                codeCoverage.analyze(covOut);
                covOut.flush();
                covOut.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            DeviceCodeCoverage totalCoverage = null;
            for (DeviceCodeCoverage cov : deviceCodeCovMap.values()) {
                if (totalCoverage == null)
                    totalCoverage = cov;
                else
                    totalCoverage.updateCoverage(cov);
            }

            if (totalCoverage != null) {
                totalCoverage.storeCoverageTtf(logDir + File.separator + CommonUtil.DevCovOutputFile);
            }
        }

        // Store uniqueErrorCovData
        if (ConfigConstants.CONFIG_STORE_UNIQUE_ERROR && !uniqueErrorCtrlCovList.isEmpty()) {
            assert uniqueErrorCtrlCovList.size() == uniqueErrorDevCovList.size();
            int uniqueErrLen = uniqueErrorCtrlCovList.size();
            try (ProgressBar pb = new ProgressBar("Printing unique error", uniqueErrLen)) {
                for (int i = 0; i < uniqueErrLen; i++) {
                    JavaCodeCoverage scenarioCtrlCov = uniqueErrorCtrlCovList.get(i);
                    CodeCoverage scenarioDevCov = uniqueErrorDevCovList.get(i);

                    // Print coverages of scenario
                    try (PrintStream fw = new PrintStream(this.uniqueErrPath + File.separator + i)) {
                        scenarioCtrlCov.analyze(fw);
                        if (scenarioDevCov != null)
                            scenarioDevCov.storeCoverageTtf(fw);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    pb.step();
                }
            }
        }
    }

    @Override
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {
        // TODO
    }
}
