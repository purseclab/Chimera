package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.*;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.util.ChimeraTTF;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4VulnType;
import io.grpc.StatusRuntimeException;
import org.apache.commons.net.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class FuzzAction {
    private static Logger log = LoggerFactory.getLogger(FuzzAction.class);
    String id;
    String state = "REQ";       // REQ, DONE
    String subState = "";       // ACCEPTED, INSTALLED, VERIFIED
    String actionCmd = null;
    FuzzActionContent content = null;           // Mutant Content
    FuzzActionContent seedContent = null;       // Original Content
    boolean isInitAction = false;
    boolean sync;
    String errorMsg = null;
    boolean doesRequireLogging = false;
    private boolean stopFuzz = false;
    EnumSet<ChimeraTTF> foundTTFSet = EnumSet.noneOf(ChimeraTTF.class);
    Exception exception = null;
    Object retObject;
    boolean isSingleIntentDpError = false;
    private IntentInterfaceResponse response = null;
    private long durationMillis;
    private int waitCnt = 1;
    boolean isFail = false;
    private boolean unsupported = false;

    private boolean executable = true;
    FuzzAction parentAction = null;
    private boolean fuzzed = false;

    public static FuzzAction loadHostAction;
    private P4VulnType p4VulnType = P4VulnType.NONE;
    private int packetType = -1;

    static {
        loadHostAction = new FuzzAction();
        loadHostAction.id = "load-hosts";
        loadHostAction.actionCmd = "load-hosts";
        loadHostAction.content = new FuzzActionContent(new JsonObject());
    }

    private FuzzAction() {}

    // Constructor for copy
    private FuzzAction(FuzzAction action) {
        this.id = action.getId();
        this.actionCmd = action.getActionCmd();
        if (action.getContent() != null)
            this.content = action.getContent().deepCopy();
        this.seedContent = action.seedContent;
        this.sync = action.isSync();
        this.isInitAction = action.isInitAction();
        this.executable = action.executable;
        this.fuzzed = action.fuzzed;
        this.parentAction = action.parentAction;
    }

    public FuzzAction(String id) {
        this.id = id;
    }

    public FuzzAction(String id, JsonObject jsonObject) throws JsonParseException {
        this.id = id;

        if (jsonObject.has("action"))
            this.actionCmd = jsonObject.get("action").getAsString();

        if (jsonObject.has("content")) {
            JsonObject contentJson = jsonObject.get("content").getAsJsonObject();
            this.content = FuzzActionContent.of(contentJson);
            this.seedContent = content.deepCopy();
        }

        if (jsonObject.has("exec-mode")) {
            String execMode = jsonObject.get("exec-mode").getAsString();
            if (execMode.toLowerCase().startsWith("async")) {
                this.sync = false;
            } else if (execMode.toLowerCase().startsWith("sync")) {
                this.sync = true;
            }
        } else {
            this.sync = isSyncCommand();
        }
    }

    public static List<FuzzAction> of(String id, JsonObject jsonObject) throws JsonParseException {
        FuzzAction newAction = new FuzzAction(id, jsonObject);
        List<FuzzAction> actions = newAction.getSubActions(true);
        if (actions.size() > 0)
            return actions;

        // If no subAction, return myself
        actions.add(newAction);
        return actions;
    }

    public static FuzzAction copy(FuzzAction action) {
        return new FuzzAction(action);
    }

    public static FuzzAction copy(FuzzAction parentAction, FuzzAction subAction) throws ParseException {
        FuzzAction newAction = new FuzzAction(parentAction);
        if (subAction != null && subAction.parentAction.equals(parentAction))
            newAction.mergeSubActions(List.of(subAction));
        return newAction;
    }

    public static FuzzAction deepcopy(FuzzAction action) {
        FuzzAction newAction = new FuzzAction(action);
        newAction.setRetObject(action.getRetObject());
        newAction.state = action.state;
        newAction.errorMsg = action.errorMsg;
        newAction.isSingleIntentDpError = action.isSingleIntentDpError;
        return newAction;
    }

    public static FuzzAction change(String actionCmd, FuzzAction action) {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);
        newAction.actionCmd = actionCmd;
        return newAction;
    }

    public static @Nonnull List<FuzzAction> fuzz(FuzzAction action)
            throws IOException, JsonSyntaxException, EndFuzzException,
            GuidanceException, StatusRuntimeException, SkipFuzzException {

        FuzzAction fuzzAction = ScenarioStore.scenarioGuidance.getRandomAction(action);
        if (fuzzAction == null)
            return new ArrayList<>();

        fuzzAction.fuzzed = true;

        List<FuzzAction> actions = fuzzAction.getSubActions(true);
        if (actions.size() > 0) {
            actions.forEach(k -> k.fuzzed = true);
            return actions;
        }

        // If no subAction, return myself
        actions.add(fuzzAction);
        return actions;
    }

    public static FuzzAction cpVerifyAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "cp-verify-intent-" + intentKey;
        fuzzAction.actionCmd = "cp-verify-intent";
        fuzzAction.content = new FuzzActionContent(new JsonObject());
        fuzzAction.content.setIntentId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    public static FuzzAction dpVerifyAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "dp-verify-intent-" + intentKey;
        fuzzAction.actionCmd = "dp-verify-intent";
        fuzzAction.content = new FuzzActionContent(new JsonObject());
        fuzzAction.content.setIntentId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    public static FuzzAction delIntentAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "del-intent-" + intentKey;
        fuzzAction.actionCmd = "del-intent";
        fuzzAction.content = new FuzzActionContent(ONOSUtil.createNewContentJson());
        fuzzAction.content.setId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    private boolean mergeSubActions(List<FuzzAction> subActions) throws ParseException {
        if (!this.actionCmd.equals("p4test"))
            return false;

        TestCase.Builder testCaseBuilder = TestCase.newBuilder(((FuzzActionP4TestContent) this.content)
                .getTestCase());

        for (FuzzAction subAction : subActions) {
            if (subAction.actionCmd.equals("add-rule")) {
                TestCase origTest = ((FuzzActionP4TestContent) subAction.content).getTestCase();
                testCaseBuilder.clearEntities()
                        .addAllEntities(origTest.getEntitiesList().stream()
                                .filter(e -> (e.getIsDefaultEntry() & 1) == 0)
                                .collect(Collectors.toList()));

            } else if (subAction.actionCmd.equals("dp-verify-rule")) {
                FuzzActionP4TestContent p4TestContent = (FuzzActionP4TestContent) subAction.content;
                testCaseBuilder.setInputPacket(p4TestContent.getInputPacket())
                        .clearExpectedOutputPacket();
                if (p4TestContent.getOutputPacket() != null && !p4TestContent.getOutputPacket().isEmpty()) {
                    testCaseBuilder.addAllExpectedOutputPacket(p4TestContent.getOutputPacket());
                }
            }
        }

        TestCase newTestCase = testCaseBuilder.build();
        JsonObject ruleJson = this.content.getContent().deepCopy();
        ruleJson.addProperty("P4Testgen", Base64.encodeBase64String(newTestCase.toByteArray()));
        this.content = new FuzzActionP4TestContent(ruleJson, newTestCase);
        this.seedContent = this.seedContent.deepCopy();

        return true;
    }

    public List<FuzzAction> getSubActions(boolean hasMyself) throws JsonParseException {
        List<FuzzAction> actionList = new ArrayList<>();
        /* currently, FuzzActionP4TestContent can only have subActions! */
        if (!(this.content instanceof FuzzActionP4TestContent))
            return actionList;

        // p4test is parent action
        if (!this.actionCmd.equals("p4test"))
            return actionList;

        this.executable = false;
        this.state = "N/A";

        if (hasMyself)
            actionList.add(this);

        JsonObject contentJson = this.content.getContent();
        contentJson.remove("ruleFilePath");
        contentJson.remove("P4Testgen");

        try {
            int idx = 0;
            String ruleSetKey = UUID.randomUUID().toString();
            contentJson.addProperty("id", ruleSetKey);

            P4Testgen.TestCase origTest = ((FuzzActionP4TestContent) this.content).getTestCase();
            P4Testgen.TestCase.Builder testCaseBuilder = TestCase.newBuilder(origTest);
            testCaseBuilder.clearEntities()
                    .addAllEntities(origTest.getEntitiesList().stream()
                    .filter(e -> (e.getIsDefaultEntry() & 1) == 0)
                    .collect(Collectors.toList()));
            P4Testgen.TestCase testCase = testCaseBuilder.build();

            FuzzAction newAction = new FuzzAction(String.format("%s-%03d", this.id, idx++));
            newAction.actionCmd = "add-rule";
            newAction.parentAction = this;
            newAction.sync = this.sync;
            JsonObject ruleJson = contentJson.deepCopy();
            ruleJson.addProperty("P4Testgen", Base64.encodeBase64String(testCase.toByteArray()));
            newAction.content = new FuzzActionP4TestContent(ruleJson, testCase);
            newAction.seedContent = newAction.content.deepCopy();
            actionList.add(newAction);

            newAction = new FuzzAction(String.format("%s-%03d", this.id, idx++));
            newAction.actionCmd = "cp-verify-rule";
            newAction.parentAction = this;
            newAction.sync = true;
            JsonObject cpVerifyJson = contentJson.deepCopy();
            newAction.content = new FuzzActionContent(cpVerifyJson);
            newAction.seedContent = newAction.content.deepCopy();
            actionList.add(newAction);

            P4Testgen.TestCase verifyTest = ((FuzzActionP4TestContent) this.content).getVerifyTest();
            newAction = new FuzzAction(String.format("%s-%03d", this.id, idx));
            newAction.actionCmd = "dp-verify-rule";
            newAction.parentAction = this;
            newAction.sync = true;
            JsonObject dpVerifyJson = contentJson.deepCopy();
            dpVerifyJson.addProperty("P4Testgen", Base64.encodeBase64String(verifyTest.toByteArray()));
            newAction.content = new FuzzActionP4TestContent(dpVerifyJson, verifyTest);
            newAction.seedContent = newAction.content.deepCopy();
            newAction.packetType = this.packetType;
            newAction.p4VulnType = this.p4VulnType;
            actionList.add(newAction);

        } catch (ParseException e) {
            log.error(e.getMessage());
            throw new JsonParseException(e.getMessage());
        }

        return actionList;
    }

    public boolean isTopoOperation() {
        String[] actionCmd = this.actionCmd.split("-");
        if (actionCmd.length != 2)
            return false;

        String elemType = actionCmd[1];
        return elemType.equals("link") || elemType.equals("device") || elemType.equals("host");
    }

    public FuzzActionContent getSeedContent() {
        return seedContent;
    }

    public void setSeedContent(FuzzActionContent content) {
        this.seedContent = content.deepCopy();
    }

    public boolean isFuzzed() {
        return fuzzed;
    }

    public boolean isExecutable() {
        return executable;
    }

    public boolean isSubAction() {
        return (parentAction != null);
    }

    public boolean isInitAction() {
        return isInitAction;
    }

    public void setInitAction() {
        isInitAction = true;
    }

    public void setSync() {
        this.sync = true;
    }

    public boolean isSync() {
        return this.sync;
    }

    public void setRandomId() {
        this.id = UUID.randomUUID().toString();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setNewIntentId() {
        this.content.setNewId();
    }

    public void setActionCmd(String actionCmd) {
        this.actionCmd = actionCmd;
    }

    public String getActionCmd() {
        return actionCmd;
    }

    public FuzzActionContent getContent() {
        return content;
    }

    public void setContent(FuzzActionContent content) {
        this.content = content;
    }

    public boolean isProcessing() {
        if (this.waitCnt > 0)
            return true;
        return (this.state.equals("REQ"));
    }

    public void success() {
        if (this.isFail)
            this.state = "ERROR";
        else
            this.state = "SUCCESS";
    }

    public boolean isSuccess() {
        return (this.state.equals("SUCCESS"));
    }

    public void error(String errorMsg) {
        this.state = "ERROR";
        this.errorMsg = errorMsg;
    }

    public Object getRetObject() {
        return retObject;
    }

    public void setRetObject(Object retObject) {
        this.retObject = retObject;
    }

    public IntentInterfaceResponse getResponse() {
        return response;
    }

    public void setResponse(IntentInterfaceResponse response) {
        this.response = response;
        if (this.response.getErrorMsg() != null)
            this.error(this.response.getErrorMsg());
    }

    public boolean doesRequireLogging() {
        return this.doesRequireLogging;
    }

    public void setReplayLogging(boolean doesRequireLogging) {
        this.doesRequireLogging = doesRequireLogging;
    }

    public void setStopFuzz(boolean stopFuzz) {
        this.stopFuzz = stopFuzz;
    }

    public boolean stopFuzz() {
        return this.stopFuzz;
    }

    public EnumSet<ChimeraTTF> getFoundTTFSet() {
        return foundTTFSet;
    }

    public void addFoundTTF(ChimeraTTF foundTTF) {
        this.foundTTFSet.add(foundTTF);
    }

    public void addAllFoundTTF(Collection<ChimeraTTF> foundTTF) {
        this.foundTTFSet.addAll(foundTTF);
    }

    public void setFoundTTF(ChimeraTTF foundTTF) {
        this.foundTTFSet.clear();
        this.foundTTFSet.add(foundTTF);
    }

    public void setSubState(String subState) {
        if (this.subState.length() > 0)
            this.subState += ",";
        this.subState += subState;
    }

    public void setException(Exception exception) {
        this.exception = exception;
    }

    public String getErrorMsg() {
        return this.errorMsg;
    }

    public boolean isError() {
        return (this.state.equals("ERROR"));
    }

    public boolean isAccepted() {
        return (this.subState.contains("ACCEPTED"));
    }

    public boolean isInstalled() {
        return (this.subState.contains("INSTALLED"));
    }

    public boolean isVerified() {
        return (this.subState.contains("VERIFIED"));
    }

    public boolean hasSyntaxError() {
        return (this.exception instanceof JsonSyntaxException);
    }

    public boolean isSingleIntentDpError() {
        return isSingleIntentDpError;
    }

    public void setSingleIntentDpError(boolean singleIntentDpError) {
        isSingleIntentDpError = singleIntentDpError;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    public void setDurationMillis(Instant start, Instant end) {
        this.durationMillis = Duration.between(start, end).toMillis();
    }

    public int decWaitCnt() {
        return --waitCnt;
    }

    public int decWaitCnt(boolean isFail) {
        if (isFail)
            this.isFail = true;
        return decWaitCnt();
    }

    public void setWaitCnt(int waitCnt) {
        this.waitCnt = waitCnt;
    }

    public void setP4VulnType(P4VulnType p4VulnType) {
        this.p4VulnType = p4VulnType;
    }

    public P4VulnType getP4VulnType() {
        return this.p4VulnType;
    }

    public void setUnsupported() {
        this.unsupported = true;
    }

    public boolean isUnsupported() {
        return this.unsupported;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    private boolean isSyncCommand() {
        if (this.actionCmd == null)
            return false;

        String cmd = this.actionCmd.toLowerCase();
        if (cmd.endsWith("verify-intent") || cmd.endsWith("-topo") || cmd.equals("del-intent")) {
            return true;
        } else if (isTopoOperation()) {
            return true;
        }

        return false;
    }

    public final JsonObject toJsonObject() throws IOException {
        return this.toJsonObject(false);
    }

    public JsonObject toJsonObject(boolean isLogging) throws IOException {
        JsonObject jsonObject = new JsonObject();

        if (this.actionCmd != null)
            jsonObject.addProperty("action", this.actionCmd);

        if (this.content != null)
            jsonObject.add("content", this.content.toJsonObject(isLogging));

        jsonObject.addProperty("exec-mode", this.sync ? "sync" : "async");
        jsonObject.addProperty("init", this.isInitAction);

        return jsonObject;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FuzzAction))
            return false;

        FuzzAction action = (FuzzAction)o;

        if (this.actionCmd == null) {
            if (action.getActionCmd() != null)
                return false;
        } else if (!this.actionCmd.equals(action.getActionCmd())) {
            return false;
        }

        if (!this.content.equals(action.getContent()))
            return false;

        if (this.sync != action.isSync())
            return false;

        return true;
    }

    public int getPacketType() {
        return packetType;
    }

    public void setPacketType(int packetType) {
        this.packetType = packetType;
    }
}
