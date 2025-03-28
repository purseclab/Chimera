package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.*;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.*;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoHost;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.ConfigTopo;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoMatrix;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ChimeraTTF;
import io.grpc.StatusRuntimeException;
import org.jacoco.core.tools.ExecFileLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.scenarioGuidance;

public class FuzzScenario implements StoreElem, Runnable {
    private static final Logger log = LoggerFactory.getLogger(FuzzScenario.class);
    private int fuzzCnt;
    boolean isFuzzed = false;
    private boolean dontFuzz = false;
    private CoverageUpdateInfo storedReason = new CoverageUpdateInfo();
    private String name;
    List<FuzzAction> actionList = new ArrayList<>();
    List<FuzzAction> failedActions = new ArrayList<>();
    List<FuzzAction> initActions = new ArrayList<>();
    List<FuzzAction> configActions = new ArrayList<>();
    List<TopoOperation> appliedTopoOperations = new ArrayList<>();
    List<TopoOperation> revertedTopoOperations = new ArrayList<>();
    int currentIdx = 0;
    ConfigTopo configTopo;
    private boolean checked;
    Thread coverageBgWorker = null;

    // Result-related data
    JavaCodeCoverage codeCoverage = new JavaCodeCoverage();
    IntentStateCoverage intentStateCoverage = new IntentStateCoverage();
    List<DeviceCodeCoverage> deviceCodeCoverages;
    List<P4Coverage> p4StatementCoverages;
    List<P4Coverage> p4ActionCoverages;
    List<RuleTraceCoverage> ruleTraceCoverages;
    List<RulePathCoverage> rulePathCoverages;
    private String errorMsg;
    boolean isInit;
    boolean isUniqueError;
    private boolean isSingleIntentDpError;      // ONOS-2 BUG

    /* logged errors */
    private String prevErrorMsg;
    private String prevErrorActionId;
    private String prevErrorActionCmd;
    private File replayFile;

    public FuzzScenario(JsonObject jsonObject) throws JsonParseException {
        if (!jsonObject.has("name"))
            throw new JsonParseException("name field missing");
        name = jsonObject.get("name").getAsString();
        fuzzCnt = 0;
        isInit = true;

        // TODO: Parse JSON in execution of Scenario, instead of constructor
        if (!jsonObject.has("actions"))
            throw new JsonParseException("actions field missing");
        JsonArray actionArr = jsonObject.get("actions").getAsJsonArray();
        int idx = 0;
        for (JsonElement action : actionArr) {
            actionList.addAll(FuzzAction.of(String.format("%s-action-%03d", name, idx++),
                    action.getAsJsonObject()));
        }

        if (jsonObject.has("errorMsg"))
            prevErrorMsg = jsonObject.get("errorMsg").getAsString();
        if (jsonObject.has("errorActionCmd"))
            prevErrorActionCmd = jsonObject.get("errorActionCmd").getAsString();
        if (jsonObject.has("errorActionId"))
            prevErrorActionId = jsonObject.get("errorActionId").getAsString();

        boolean loadHost = false;
        // TODO: Check topology and build initActions in execution of Scenario, instead of contructor
        if (jsonObject.has("topology")) {
            JsonObject topoJson = jsonObject.get("topology").getAsJsonObject();
            if (topoJson.has("configTopo")) {
                configTopo = new ConfigTopo();
                configTopo.setConfig(topoJson.get("configTopo").getAsJsonObject());
                checked = false;
            }

            JsonObject initActionJson = new JsonObject();
            initActionJson.addProperty("action", "create-topo");
            initActionJson.add("content", topoJson);

            FuzzAction createTopoAction = new FuzzAction(String.format("%s-init", name), initActionJson);
            createTopoAction.setSync();

            initActions.add(createTopoAction);
            loadHost = true;
        }

        if (jsonObject.has("topoOperations")) {
            idx = 1;
            JsonArray topoOperationJsonArr = jsonObject.get("topoOperations").getAsJsonArray();

            for (JsonElement topoOperationJsonElem : topoOperationJsonArr) {
                JsonObject topoOperationJson = topoOperationJsonElem.getAsJsonObject();
                TopoOperation topoOperation = new TopoOperation(topoOperationJson);

                if (topoOperation.getElem() instanceof TopoHost)
                    loadHost = true;

                appliedTopoOperations.add(topoOperation);
                initActions.add(new FuzzAction(String.format("%s-init-%03d", name, idx++), topoOperationJson));
            }
        }

        if (loadHost)
            initActions.add(FuzzAction.loadHostAction);

        if (jsonObject.has("configActions")) {
            idx = 1;
            JsonArray configActionsJsonArr = jsonObject.get("configActions").getAsJsonArray();

            for (JsonElement configActionsJsonElem : configActionsJsonArr) {
                JsonObject configActionJson = configActionsJsonElem.getAsJsonObject();
                FuzzAction configFuzzAction = new FuzzAction(String.format("%s-config-%03d", name, idx++), configActionJson);
                configFuzzAction.setSync();
//                if (initFuzzAction.getActionCmd().equals("add-host"))
//                    loadHost = true;
                configActions.add(configFuzzAction);
            }
        }

        for (FuzzAction initAction : initActions) {
            initAction.setInitAction();
        }
    }

    public FuzzScenario(JsonObject jsonObject, boolean loadHost) throws JsonParseException {
        if (!jsonObject.has("name"))
            throw new JsonParseException("name field missing");
        name = jsonObject.get("name").getAsString();
        fuzzCnt = 0;
        isInit = true;

        // TODO: Parse JSON in execution of Scenario, instead of constructor
        if (!jsonObject.has("actions"))
            throw new JsonParseException("actions field missing");
        JsonArray actionArr = jsonObject.get("actions").getAsJsonArray();
        int idx = 0;
        for (JsonElement action : actionArr) {
            actionList.addAll(FuzzAction.of(String.format("%s-action-%03d", name, idx++),
                    action.getAsJsonObject()));
        }

        if (jsonObject.has("errorMsg"))
            prevErrorMsg = jsonObject.get("errorMsg").getAsString();
        if (jsonObject.has("errorActionCmd"))
            prevErrorActionCmd = jsonObject.get("errorActionCmd").getAsString();
        if (jsonObject.has("errorActionId"))
            prevErrorActionId = jsonObject.get("errorActionId").getAsString();

        // TODO: Check topology and build initActions in execution of Scenario, instead of contructor
        if (jsonObject.has("topology")) {
            JsonObject topoJson = jsonObject.get("topology").getAsJsonObject();
            if (topoJson.has("configTopo")) {
                configTopo = new ConfigTopo();
                configTopo.setConfig(topoJson.get("configTopo").getAsJsonObject());
                checked = false;
            }

            JsonObject initActionJson = new JsonObject();
            initActionJson.addProperty("action", "create-topo");
            initActionJson.add("content", topoJson);

            FuzzAction createTopoAction = new FuzzAction(String.format("%s-init", name), initActionJson);
            createTopoAction.setSync();

            initActions.add(createTopoAction);
        } else {
            loadHost = false;
        }

        if (jsonObject.has("topoOperations")) {
            idx = 1;
            JsonArray topoOperationJsonArr = jsonObject.get("topoOperations").getAsJsonArray();

            for (JsonElement topoOperationJsonElem : topoOperationJsonArr) {
                JsonObject topoOperationJson = topoOperationJsonElem.getAsJsonObject();
                TopoOperation topoOperation = new TopoOperation(topoOperationJson);

                appliedTopoOperations.add(topoOperation);
                initActions.add(new FuzzAction(String.format("%s-init-%03d", name, idx++), topoOperationJson));
            }
        }

        if (loadHost)
            initActions.add(FuzzAction.loadHostAction);

        if (jsonObject.has("configActions")) {
            idx = 1;
            JsonArray configActionsJsonArr = jsonObject.get("configActions").getAsJsonArray();

            for (JsonElement configActionsJsonElem : configActionsJsonArr) {
                JsonObject configActionJson = configActionsJsonElem.getAsJsonObject();
                FuzzAction configFuzzAction = new FuzzAction(String.format("%s-config-%03d", name, idx++), configActionJson);
                configFuzzAction.setSync();
//                if (initFuzzAction.getActionCmd().equals("add-host"))
//                    loadHost = true;
                configActions.add(configFuzzAction);
            }
        }

        for (FuzzAction initAction : initActions) {
            initAction.setInitAction();
        }
    }
    private FuzzScenario(FuzzScenario scenario) {
        name = scenario.getName();
        fuzzCnt = scenario.getFuzzCnt();
        configTopo = scenario.getConfigTopo();
        checked = scenario.checked;
        appliedTopoOperations = scenario.appliedTopoOperations;
        isFuzzed = scenario.isFuzzed;
        isInit = false;
    }

    private static final int RANDOM_ADD_INTENT      = 0;
    private static final int RANDOM_DEL_INTENT      = 1;
    private static final int RANDOM_MOD_INTENT      = 2;
    private static final int RANDOM_MUTATE_TOPO     = 3;
    private static final int RANDOM_FUZZ_OPER_MAX   = 2;

    private static final int INTENT_SYNC_BIT        = 1;
    private static final int INTENT_REMOVED_BIT     = 1 << 1;

    @Deprecated
    public static FuzzScenario fuzz(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException,
            GuidanceException, StatusRuntimeException, SkipFuzzException {
        return scenarioGuidance.getRandomScenario(scenario);
    }

    public static FuzzScenario copy(FuzzScenario scenario) {
        return copy(scenario, null);
    }

    public static FuzzScenario copy(FuzzScenario scenario, FuzzAction fuzzAction) {
        FuzzScenario newScenario = new FuzzScenario(scenario);

        // 1. Copy configActions
        for (FuzzAction configAction : scenario.getConfigActions()) {
            newScenario.addConfigAction(FuzzAction.copy(configAction));
        }

        // 2. If fuzzAction exists, copy given fuzzAction, instead of one in scenario.
        List<FuzzAction> copiedActions = new ArrayList<>();
        if (fuzzAction != null) {
            if (fuzzAction.isSubAction()) {
                // 1) If it is subAction, copy its parentAction and sibling subActions.
                try {
                    FuzzAction parentAction = FuzzAction.copy(fuzzAction.parentAction, fuzzAction);
                    copiedActions.add(parentAction);
                    copiedActions.addAll(parentAction.getSubActions(false));
                } catch (ParseException e) {
                    log.error(e.getMessage());
                }
            } else {
                // 2) Otherwise, copy itself
                copiedActions.add(FuzzAction.copy(fuzzAction));
            }
        }

        // 3. Copy all actions in scenario and already-copied actions
        Map<FuzzAction, FuzzAction> newScenarioActionMap = new LinkedHashMap<>();
        for (FuzzAction action : scenario.getActionList()) {
            boolean copied = false;
            for (FuzzAction copiedAction : copiedActions) {
                if (copiedAction.getActionCmd().equals(action.getActionCmd())) {
                    newScenarioActionMap.put(action, copiedAction);
                    copied = true;
                    break;
                }
            }

            if (copied)
                continue;

            FuzzAction newAction = FuzzAction.copy(action);
            // Set parentAction with copied one!
            if (action.isSubAction()) {
                newAction.parentAction = newScenarioActionMap.get(action.parentAction);
            }
            newScenario.addAction(newAction);
        }

        // 4. Copy actionMap values
        newScenario.addAction(newScenarioActionMap.values());

        return newScenario;
    }

    public static FuzzScenario deepcopy(FuzzScenario scenario) {
        FuzzScenario newScenario = new FuzzScenario(scenario);

        for (FuzzAction configAction : scenario.getConfigActions()) {
            newScenario.addConfigAction(FuzzAction.deepcopy(configAction));
        }

        for (FuzzAction action : scenario.getActionList()) {
            newScenario.addAction(FuzzAction.deepcopy(action));
        }

        return newScenario;
    }

    public String getName() {
        return name;
    }

    public void setFuzzed(boolean fuzzed) {
        isFuzzed = fuzzed;
    }

    public boolean isFuzzed() {
        return this.isFuzzed;
    }

    public void setFuzzCnt(int fuzzCnt) {
        this.fuzzCnt = fuzzCnt;
    }

    public int getFuzzCnt() {
        return fuzzCnt;
    }

    public void incFuzzCnt() {
        this.fuzzCnt ++;
    }

    public void dontFuzz() {
        this.dontFuzz = true;
    }

    public boolean canFuzz() {
        return !this.dontFuzz;
    }

    public void dontStoreSeed(CoverageUpdateInfo reason) {
        // specify reason why it is already stored
        this.storedReason.merge(reason);
    }

    public boolean doesStoreSeed(CoverageUpdateInfo reason) {
        // If there is no stored reason, store this as seed
        if (!this.storedReason.isUpdated())
            return true;

        for (String covName : reason.getAllUpdatedCoverageNames()) {
            // If already stored reason doesn't match to given, store this as seed
            if (!this.storedReason.isUpdated(covName))
                return true;
        }

        return false;
    }

    public boolean isDone() {
        return currentIdx >= actionList.size();
    }

    public FuzzAction getNextAction() {
        if (this.isDone())
            return null;

        return (actionList.get(currentIdx++));
    }

    public List<FuzzAction> getInitActions() {
        return initActions;
    }

    public boolean addInitAction(FuzzAction initAction) {
        return initActions.add(initAction);
    }

    public List<FuzzAction> getConfigActions() {
        return configActions;
    }

    public boolean addConfigAction(FuzzAction configAction) {
        return configActions.add(configAction);
    }

    public boolean addConfigAction(List<FuzzAction> configActionList) {
        return this.configActions.addAll(configActionList);
    }

    public boolean isError() {
        if (errorMsg != null)
            return true;

        for (FuzzAction action : actionList) {
            if (action.isError())
                return true;
        }

        return false;
    }

    public void setError(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public String getErrorMsg() {
        if (this.errorMsg != null)
            return errorMsg;

        String msg = null;
        for (FuzzAction action : actionList) {
            if (action.isError()) {
                msg = action.getId() + ":" + action.errorMsg;
                if (!action.isSingleIntentDpError)
                    return msg;
            }
        }

        return msg;
    }

    public FuzzAction getErrorAction() {
        for (FuzzAction action : actionList) {
            if (action.isError()) {
                return action;
            }
        }

        return null;
    }

    public boolean isSuccess() {
        if (errorMsg != null)
            return false;

        for (FuzzAction action : actionList) {
            if (!action.isExecutable())
                continue;

            if (!action.isSuccess())
                return false;
        }

        return true;
    }

    public boolean hasSyntaxError() {
        for (FuzzAction action : actionList) {
            if (!action.hasSyntaxError())
                return false;
        }

        return true;
    }

    public boolean doesRequireLogging() {
        for (FuzzAction action : actionList) {
            if (action.doesRequireLogging())
                return true;
        }

        return false;
    }

    public boolean stopFuzz() {
        for (FuzzAction action : actionList) {
            if (action.stopFuzz())
                return true;
        }

        return false;
    }

    public EnumSet<ChimeraTTF> getFoundTTFSet() {
        EnumSet<ChimeraTTF> foundTTFSet = EnumSet.noneOf(ChimeraTTF.class);
        for (FuzzAction action : actionList) {
            foundTTFSet.addAll(action.getFoundTTFSet());
        }
        return foundTTFSet;
    }

    public boolean isAccepted() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isAccepted())
                return true;
        }

        return false;
    }

    public boolean isInstalled() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isInstalled())
                return true;
        }

        return false;
    }

    public boolean isVerified() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isVerified())
                return true;
        }

        return false;
    }

    public void addAction(FuzzAction action) {
        this.actionList.add(action);
    }

    public void addAction(@Nonnull Collection<FuzzAction> actionList) {
        this.actionList.addAll(actionList);
    }

    public List<FuzzAction> getActionList() {
        return actionList;
    }

    public boolean replaceAction(FuzzAction oldAction, FuzzAction newAction) {
        boolean found = false;

        // 1) replace oldAction to newAction
        for (int i = 0; i < this.actionList.size(); i++) {
            if (this.actionList.get(i).equals(oldAction)) {
                this.actionList.set(i, newAction);
                found = true;
            }
        }

        if (found) {
            // 2) remove if parent of subActions is oldAction
            this.actionList.removeIf(action -> action.parentAction == oldAction);

            // 3) add new subActions
            this.actionList.addAll(newAction.getSubActions(false));
        }

        return found;
    }

    public void clearActionList() {
        actionList.clear();
    }
//    public void clearInitActionList() {
//        initActions.clear();
//    }
    public void clearConfigActions() {
        configActions.clear();
    }

    public ConfigTopo getConfigTopo() {
        return configTopo;
    }

    public void setConfigTopo(ConfigTopo configTopo) {
        this.configTopo = configTopo;
    }

    public boolean requireConfigTopo() {
        if (configTopo == null)
            return false;

        if (checked)
            return false;

        return true;
    }

    public JavaCodeCoverage getCodeCoverage() {
        return codeCoverage;
    }

    public boolean applyCodeCoverage(ExecFileLoader loader) {
        return codeCoverage.applyLoader(loader);
    }

    public void startCoverageBgWorker() {
        coverageBgWorker = new Thread(this);
        log.debug("Start bg worker thread: " + coverageBgWorker.getId());
        coverageBgWorker.start();
    }

    public void stopCoverageBgWorker() {
        if (coverageBgWorker != null && coverageBgWorker.isAlive()) {
            log.debug("Stop bg worker thread: " + coverageBgWorker.getId());
            coverageBgWorker.interrupt();
            try {
                coverageBgWorker.join();
            } catch (InterruptedException ignore) {}
            coverageBgWorker = null;
        }
    }

    public List<DeviceCodeCoverage> getDeviceCodeCoverages() {
        return this.deviceCodeCoverages;
    }

    public @Nullable DeviceCodeCoverage getDeviceCodeCoverage(String deviceId) {
        for (DeviceCodeCoverage deviceCodeCoverage : this.deviceCodeCoverages) {
            if (deviceCodeCoverage.getDeviceId().equals(deviceId))
                return deviceCodeCoverage;
        }
        return null;
    }

    public CoverageUpdateInfo applyDeviceCodeCoverages(List<DeviceCodeCoverage> coverages) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (this.deviceCodeCoverages == null) {
            this.deviceCodeCoverages = new ArrayList<>(coverages);
            for (DeviceCodeCoverage coverage : coverages) {
                String subKey = coverage.getDeviceId().substring("device:".length());
                reason.hasUpdated("DC" + subKey, coverage);
            }

        } else {
            for (DeviceCodeCoverage coverage : coverages) {
                Optional<DeviceCodeCoverage> deviceCodeCoverage = this.deviceCodeCoverages.stream()
                        .filter(k -> k.getDeviceId().equals(coverage.getDeviceId()))
                        .findFirst();

                String subKey = coverage.getDeviceId().substring("device:".length());

                if (deviceCodeCoverage.isPresent()) {
                    if (deviceCodeCoverage.get().updateCoverage(coverage))
                        reason.hasUpdated("DC" + subKey, coverage);

                } else {
                    this.deviceCodeCoverages.add(coverage);
                    reason.hasUpdated("DC" + subKey, coverage);
                }
            }
        }

        return reason;
    }

    public List<P4Coverage> getP4StatementCoverages() {
        return this.p4StatementCoverages;
    }

    public @Nullable P4Coverage getP4StatementCoverage(String deviceId) {
        for (P4Coverage p4StatementCoverage : this.p4StatementCoverages) {
            if (p4StatementCoverage.getDeviceId().equals(deviceId))
                return p4StatementCoverage;
        }
        return null;
    }

    public CoverageUpdateInfo applyP4StatementCoverages(List<P4Coverage> coverages) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (this.p4StatementCoverages == null) {
            this.p4StatementCoverages = new ArrayList<>(coverages);
            for (P4Coverage coverage : coverages) {
                String subKey = coverage.getDeviceId().substring("device:".length());
                reason.hasUpdated("PS" + subKey, coverage);
            }

        } else {
            for (P4Coverage coverage : coverages) {
                Optional<P4Coverage> p4StatementCoverage = this.p4StatementCoverages.stream()
                        .filter(k -> k.getDeviceId().equals(coverage.getDeviceId()))
                        .findFirst();

                String subKey = coverage.getDeviceId().substring("device:".length());

                if (p4StatementCoverage.isPresent()) {
                    if (p4StatementCoverage.get().updateCoverage(coverage))
                        reason.hasUpdated("PS" + subKey, coverage);

                } else {
                    this.p4StatementCoverages.add(coverage);
                    reason.hasUpdated("PS" + subKey, coverage);
                }
            }
        }

        return reason;
    }

    public List<P4Coverage> getP4ActionCoverages() {
        return this.p4ActionCoverages;
    }

    public @Nullable P4Coverage getP4ActionCoverage(String deviceId) {
        for (P4Coverage p4ActionCoverage : this.p4ActionCoverages) {
            if (p4ActionCoverage.getDeviceId().equals(deviceId))
                return p4ActionCoverage;
        }
        return null;
    }

    public CoverageUpdateInfo applyP4ActionCoverages(List<P4Coverage> coverages) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (this.p4ActionCoverages == null) {
            this.p4ActionCoverages = new ArrayList<>(coverages);
            for (P4Coverage coverage : coverages) {
                String subKey = coverage.getDeviceId().substring("device:".length());
                reason.hasUpdated("PA" + subKey, coverage);
            }

        } else {
            for (P4Coverage coverage : coverages) {
                Optional<P4Coverage> p4ActionCoverage = this.p4ActionCoverages.stream()
                        .filter(k -> k.getDeviceId().equals(coverage.getDeviceId()))
                        .findFirst();

                String subKey = coverage.getDeviceId().substring("device:".length());

                if (p4ActionCoverage.isPresent()) {
                    if (p4ActionCoverage.get().updateCoverage(coverage))
                        reason.hasUpdated("PA" + subKey, coverage);

                } else {
                    this.p4ActionCoverages.add(coverage);
                    reason.hasUpdated("PA" + subKey, coverage);
                }
            }
        }

        return reason;
    }

    public List<RuleTraceCoverage> getRuleTraceCoverages() {
        return this.ruleTraceCoverages;
    }

    public @Nullable RuleTraceCoverage getRuleTraceCoverage(String ruleKey) {
        for (RuleTraceCoverage ruleTraceCoverage : this.ruleTraceCoverages) {
            if (ruleTraceCoverage.getRuleKey().equals(ruleKey))
                return ruleTraceCoverage;
        }
        return null;
    }

    public CoverageUpdateInfo applyRuleTraceCoverages(List<RuleTraceCoverage> coverages) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (this.ruleTraceCoverages == null) {
            this.ruleTraceCoverages = new ArrayList<>(coverages);
            for (RuleTraceCoverage coverage : coverages) {
                String ruleKey = coverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
                reason.hasUpdated("RT" + subKey, coverage);
            }

        } else {
            for (RuleTraceCoverage coverage : coverages) {
                Optional<RuleTraceCoverage> ruleTraceCoverage = this.ruleTraceCoverages.stream()
                        .filter(k -> k.getRuleKey().equals(coverage.getRuleKey()))
                        .findFirst();

                String ruleKey = coverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));

                if (ruleTraceCoverage.isPresent()) {
                    if (ruleTraceCoverage.get().updateCoverage(coverage))
                        reason.hasUpdated("RT" + subKey, coverage);

                } else {
                    this.ruleTraceCoverages.add(coverage);
                    reason.hasUpdated("RT" + subKey, coverage);
                }
            }
        }

        return reason;
    }

    public List<RulePathCoverage> getRulePathCoverages() {
        return this.rulePathCoverages;
    }

    public @Nullable RulePathCoverage getRulePathCoverage(String ruleKey) {
        for (RulePathCoverage rulePathCoverage : this.rulePathCoverages) {
            if (rulePathCoverage.getRuleKey().equals(ruleKey))
                return rulePathCoverage;
        }
        return null;
    }

    public CoverageUpdateInfo applyRulePathCoverages(List<RulePathCoverage> coverages) {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (this.rulePathCoverages == null) {
            this.rulePathCoverages = new ArrayList<>(coverages);
            for (RulePathCoverage coverage : coverages) {
                String ruleKey = coverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));
                reason.hasUpdated("RP" + subKey, coverage);
            }

        } else {
            for (RulePathCoverage coverage : coverages) {
                Optional<RulePathCoverage> rulePathCoverage = this.rulePathCoverages.stream()
                        .filter(k -> k.getRuleKey().equals(coverage.getRuleKey()))
                        .findFirst();

                String ruleKey = coverage.getRuleKey();
                String subKey = ruleKey.substring(0, Integer.min(6, ruleKey.length()));

                if (rulePathCoverage.isPresent()) {
                    if (rulePathCoverage.get().updateCoverage(coverage))
                        reason.hasUpdated("RP" + subKey, coverage);

                } else {
                    this.rulePathCoverages.add(coverage);
                    reason.hasUpdated("RP" + subKey, coverage);
                }
            }
        }

        return reason;
    }

    @Override
    public void run() {
        while (!Thread.interrupted()) {
            try {
                scenarioGuidance.measureCoverage(this, null,
                        false, false, true);
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (FuzzCommand.statOut != null) {
                if (this.codeCoverage != null && this.codeCoverage.isAnalyzed()) {
                    String statStr = scenarioGuidance.getStatsString(this);
                    if (statStr != null) {
                        FuzzCommand.statOut.printf("%s [BG]\n", statStr);
                        FuzzCommand.statOut.flush();
                    }
                }
            }

            try {
                Thread.sleep(1000 * ConfigConstants.CONFIG_MEASURE_STAT_INTERVAL);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public IntentStateCoverage getIntentStateCoverage() {
        return this.intentStateCoverage;
    }

    public void applyIntentStateCoverage(FuzzAction action) throws UnsupportedOperationException {
        applyIntentStateCoverage(action, null);
    }

    public void applyIntentStateCoverage(FuzzAction action, Object retObject) throws UnsupportedOperationException {
        this.intentStateCoverage.applyAction(action, retObject);
    }

    public void logAction(FuzzAction action) {
        this.intentStateCoverage.logAction(action);
    }

    public boolean isInit() {
        return isInit;
    }

    public boolean isUniqueError() {
        return isUniqueError;
    }

    public void setUniqueError() {
        isUniqueError = true;
    }

    public boolean isSingleIntentDpError() {
        return isSingleIntentDpError;
    }

    public void setSingleIntentDpError(boolean singleIntentDpError) {
        isSingleIntentDpError = singleIntentDpError;
    }

    public boolean addTopoOperation(TopoOperation topoOperation) {
        return this.appliedTopoOperations.add(topoOperation);
    }

    public boolean updateTopoOperations(TopoMatrix topoMatrix) {
        this.appliedTopoOperations.clear();
        return this.appliedTopoOperations.addAll(topoMatrix.getAppliedTopoOperations());
    }

    public boolean updateTopoOperation(TopoOperation oldOperation, TopoOperation newOperation) {
        int idx = appliedTopoOperations.indexOf(oldOperation);
        if (idx < 0)
            return false;

        appliedTopoOperations.set(idx, newOperation);
        return true;
    }

    /*
     * cmpResult(): compares previous result and current result
     * Returns -1 (wasError), 0 (same), 1 (isError)
     */
    public int cmpResult() {
        boolean wasError = (this.prevErrorMsg != null);
        boolean isError = (this.getErrorMsg() != null);

        // 1. Diff result
        if (wasError != isError) {
            if (wasError)
                return 1;
            return -1;
        }

        // 2. No error
        if (!wasError)
            return 0;

        // 3. compare errorMsg
        for (FuzzAction action : actionList) {
            if (action.isError()) {
                // 3-1. errorActionCmd
                if (this.prevErrorActionCmd != null &&
                        !action.getActionCmd().equals(this.prevErrorActionCmd)) {
                    log.error("Diff errorCmd: {} -> {}", this.prevErrorActionCmd, action.getActionCmd());
                    return 1;
                }

                // 3-2. errorMsg
                if (!action.getErrorMsg().equals(this.prevErrorMsg)) {
                    log.error("Diff errorMsg in {}: {} -> {}", action.getActionCmd(),
                            this.prevErrorMsg,
                            action.getErrorMsg());
                    return 1;
                }

                return 0;
            }
        }

        // Return different error
        return 1;
    }

    public File getReplayFile() {
        return replayFile;
    }

    public void setReplayFile(File replayFile) {
        this.replayFile = replayFile;
    }


    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    public String getResult() {
        return String.format("[%s:%d] %s", this.getName(), this.getFuzzCnt(),
                this.isSuccess() ? "SUCCESS" :
                this.isError() ? "ERROR: " + this.getErrorMsg() :
                "processing ...");
    }

    public String prevResult() {
        return String.format("%s", this.prevErrorMsg == null ? "SUCCESS" :
                ("ERROR: " + this.prevErrorMsg +
                        (this.prevErrorActionCmd == null ? "" : " at " + this.prevErrorActionCmd)));
    }

    public final JsonObject toJsonObject() throws IOException {
        return this.toJsonObject(false, null);
    }

    public JsonObject toJsonObject(boolean isLogging, FuzzAction errorAction) throws IOException {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("name", this.name);

        if (this.configTopo != null) {
            // TODO: log controller setting
            JsonObject configTopoJson = new JsonObject();
            configTopoJson.add("configTopo", this.configTopo.getConfigJson());
            jsonObject.add("topology", configTopoJson);

            if (this.appliedTopoOperations.size() > 0) {
                JsonArray topoOperationJsonArr = new JsonArray();

                for (TopoOperation topoOperation : this.appliedTopoOperations) {
                    topoOperationJsonArr.add(topoOperation.toFuzzActionJson());
                }

                jsonObject.add("topoOperations", topoOperationJsonArr);
            }
        }

        JsonArray configActionJsonArray = new JsonArray();
        for (FuzzAction configAction : getConfigActions()) {
            configActionJsonArray.add(configAction.toJsonObject(isLogging));
        }
        jsonObject.add("configActions", configActionJsonArray);

        JsonArray actionJsonArray = new JsonArray();
        for (FuzzAction action : getActionList()) {
            if (action.isSubAction())
                continue;
            actionJsonArray.add(action.toJsonObject(isLogging));
        }
        jsonObject.add("actions", actionJsonArray);

        JsonObject resultObject = new JsonObject();
        resultObject.addProperty("isAccepted", isAccepted());
        resultObject.addProperty("isInstalled", isInstalled());
        resultObject.addProperty("isVerified", isVerified());
        resultObject.addProperty("isSuccess", isSuccess());
        jsonObject.add("result", resultObject);

        if (errorAction != null) {
            jsonObject.addProperty("errorMsg", errorAction.getErrorMsg());
            jsonObject.addProperty("errorActionCmd", errorAction.getActionCmd());
            jsonObject.addProperty("errorActionId", errorAction.getId());

        } else if (this.errorMsg != null) {
            jsonObject.addProperty("errorMsg", errorMsg);

        } else {
            FuzzAction inErrorAction = null;
            for (FuzzAction action : actionList) {
                if (action.isError()) {
                    inErrorAction = action;
                    break;
                }
            }

            if (inErrorAction != null) {
                jsonObject.addProperty("errorMsg", inErrorAction.getErrorMsg());
                jsonObject.addProperty("errorActionCmd", inErrorAction.getActionCmd());
                jsonObject.addProperty("errorActionId", inErrorAction.getId());
            }
        }

        return jsonObject;
    }

    public JsonObject toRuntimeJsonObject() throws IOException {
        JsonObject jsonObject = new JsonObject();

        if (this.configTopo != null) {
            // TODO: log controller setting
            JsonObject configTopoJson = new JsonObject();
            configTopoJson.add("configTopo", this.configTopo.getConfigJson());
            jsonObject.add("topology", configTopoJson);

            if (this.appliedTopoOperations.size() > 0) {
                JsonArray topoOperationJsonArr = new JsonArray();

                for (TopoOperation topoOperation : this.appliedTopoOperations) {
                    topoOperationJsonArr.add(topoOperation.toFuzzActionJson());
                }

                jsonObject.add("topoOperations", topoOperationJsonArr);
            }
        }

        JsonArray configActionJsonArray = new JsonArray();
        for (FuzzAction configAction : getConfigActions()) {
            configActionJsonArray.add(configAction.toJsonObject(false));
        }
        jsonObject.add("configActions", configActionJsonArray);

        JsonArray actionJsonArray = new JsonArray();
        for (FuzzAction action : getActionList()) {
            if (action.isSubAction())
                continue;
            actionJsonArray.add(action.toJsonObject(false));
        }
        jsonObject.add("actions", actionJsonArray);

        return jsonObject;
    }

    public void logScenario(String fileName) {
        logScenario(fileName, null);
    }

    public void logScenario(String fileName, FuzzAction errorAction) {
        if (this.isUniqueError())
            fileName += "-unique";
        fileName += ".json";
        try (FileWriter fileWriter = new FileWriter(fileName)) {
            Gson gson = new Gson();
            gson.toJson(this.toJsonObject(true, errorAction), fileWriter);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FuzzScenario))
            return false;

        try {
            return this.toRuntimeJsonObject().equals(((FuzzScenario) obj).toRuntimeJsonObject());
        } catch (IOException e) {
            return false;
        }
    }
}
