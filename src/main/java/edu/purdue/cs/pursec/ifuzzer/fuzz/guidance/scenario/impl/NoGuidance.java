package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.FuzzIntentScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.JavaCodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

public class NoGuidance extends FuzzIntentScenarioGuidance {

    private static Logger log = LoggerFactory.getLogger(NoGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    FuzzIntentGuidance intentGuidance;
    TopologyIntentGuidance topologyIntentGuidance;
    JavaCodeCoverage codeCoverage;
    List<FuzzScenario> seedScenarios = new LinkedList<>();
    private int prevHitCount = 0;
    private int curSeedIdx = -1, numCycles = 0;
    private static final IntentStore configIntentStore = IntentStore.getConfigInstance();
    private static final Random rand = new Random();
    private static final boolean isPazz = ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance");

    public NoGuidance()  throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl."
                + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
        topologyIntentGuidance = new TopologyIntentGuidance();
    }

    @Override
    public void init(Object o, String resultDirPath) throws IOException, InterruptedException {
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

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {

        // store given scenario into seed
        if (codeCoverage != null) {
            int curHitCount = codeCoverage.getHitCount();
            if (prevHitCount < curHitCount) {
                // Guidance finds new coverage path
                seedScenarios.add(scenario);

                log.info("## Add new matrix {} -> {} into seeds: {} | cycle {} ##",
                        prevHitCount, curHitCount,
                        seedScenarios.size(), numCycles);
                prevHitCount = curHitCount;
            }
        }

        // Run once again
        if (seedScenarios.size() == 0)
            return FuzzScenario.copy(scenario);

        curSeedIdx = (curSeedIdx + 1) % seedScenarios.size();
        if (curSeedIdx == 0)
            numCycles++;
        FuzzScenario seedScenario = seedScenarios.get(curSeedIdx);
        FuzzScenario newScenario = FuzzScenario.copy(seedScenario);
        newScenario.setFuzzCnt(scenario.getFuzzCnt());

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

        newScenario.clearActionList();

        Set<String> toBeVerifiedIntentIdSet = new HashSet<>();
        TopoOperation prevOperation = null;
        Stack<TopoOperation> appliedTopoOperations = new Stack<>();
        int numActions = rand.nextInt(5) + 1;
        for (int i = 0; i < numActions; i++) {
            // purely generate random action.
            FuzzAction newAction = new FuzzAction(String.format("%s-rand-%03d", newScenario.getName(), i + 1));

            String randomIntentStr;
            FuzzActionContent newContent;
            Intent targetIntent;
            String targetId;
            while (true) {
                int caseNum = rand.nextInt(5);

                // If there was no intent action, add-intent
                if (i == numActions - 1 && configIntentStore.getAllIntents().size() == 0)
                    caseNum = 0;

                // If pazz fuzzing, do not test other operations!
                if (isPazz)
                    caseNum = 0;

                switch (caseNum) {
                    case 0:
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
                        toBeVerifiedIntentIdSet.add(newContent.getId());
                        break;

                    case 1:
                        // mod-intent
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, true);
                        if (targetId == null)
                            continue;
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
                        toBeVerifiedIntentIdSet.add(newContent.getId());
                        break;

                    case 2:
                        // withdraw-intent (TODO: withdraw unknown intent)
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, false);
                        if (targetId == null)
                            continue;
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (!targetIntent.getState().equals(State.REMOVED)) {
                            targetIntent.setState(State.WITHDRAWN);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("withdraw-intent");
                        newAction.setSync();
                        toBeVerifiedIntentIdSet.add(newContent.getId());

                        break;

                    case 3:
                        // purge-intent
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, false);
                        if (targetId == null)
                            continue;
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (targetIntent.getState().equals(State.WITHDRAWN)) {
                            targetIntent.setState(State.REMOVED);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("purge-intent");
                        newAction.setSync();
                        toBeVerifiedIntentIdSet.add(newContent.getId());

                        break;

                    case 4:
                        // topology operation
                        // Get random operations from current matrix
                        List<Intent> workingIntents = new ArrayList<>();
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.INSTALLED).values());
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.FAILED).values());

                        TopoOperation topoOperation;
                        while (true) {
                            topoOperation = topologyIntentGuidance.getRandomTopoOperationFromCurMatrix(prevOperation);
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
                            configIntentStore.recomputeIntents(configTopoGraph, toBeVerifiedIntentIdSet);
                            break;
                        }

                        appliedTopoOperations.push(topoOperation);
                        prevOperation = topoOperation;
                        topologyIntentGuidance.resetMatrix();
                        newAction = topoOperation.toFuzzAction(String.format("%s-rand-%03d", newScenario.getName(), i + 1));
                        newAction.setSync();
                        break;

                    default:
                        break;
                }

                // successfully generate operation
                break;
            }

            newScenario.addAction(newAction);
        }

        // Add verify action
        int i = 1;
        for (String key : toBeVerifiedIntentIdSet) {
            JsonObject contentJson = new JsonObject();
            contentJson.addProperty("intentId", key);

            FuzzAction verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i++));
            verifyAction.setContent(new FuzzActionContent(contentJson));
            verifyAction.setActionCmd("cp-verify-intent");
            newScenario.addAction(verifyAction);

            if (!isPazz) {
                verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i++));
                verifyAction.setContent(new FuzzActionContent(contentJson));
                verifyAction.setActionCmd("dp-verify-intent");
                newScenario.addAction(verifyAction);
            }
        }

        if (isPazz) {
            FuzzAction verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i));
            verifyAction.setActionCmd("dp-verify-intent");
            newScenario.addAction(verifyAction);
        }

        newScenario.incFuzzCnt();
        newScenario.setFuzzed(true);

        // revert configTopoGraph
        while (!appliedTopoOperations.isEmpty()) {
            configTopoGraph.applyTopoOperation(appliedTopoOperations.pop().invert());
        }

        return newScenario;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        if (codeCoverage == null)
            codeCoverage = new JavaCodeCoverage();

        codeCoverage.updateCoverage(fuzzScenario.getCodeCoverage());

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
        return intentGuidance.getStatsHeader();
    }

    @Override
    public String getStatsString() {
        return intentGuidance.getStatsString();
    }

    @Override
    public String getResultsString() {
        return intentGuidance.getResultsString();
    }

    @Override
    public void storeMetadata(String logDir) {}

    @Override
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {
        // TODO
    }
}
