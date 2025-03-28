package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl;

import com.github.difflib.DiffUtils;
import com.github.difflib.patch.AbstractDelta;
import com.github.difflib.patch.Patch;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.api.FuzzP4RuleGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.FuzzP4PacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl.FP4PacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.P4SeedCorpusPolicy;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedScenario;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.impl.ScenarioSeedCorpora;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzActionP4TestContent;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.*;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4KnownBugType;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4CoverageReplyWithError;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4VulnType;
import io.grpc.StatusRuntimeException;
import me.tongfei.progressbar.ProgressBar;
import org.apache.commons.net.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4testgen.P4Testgen;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/*
 * Combination of SingleP4Rule + GenP4
 */
public class P4CodeCovGuidance extends FuzzScenarioGuidance {
    private static final P4Util p4UtilInstance = P4Util.getInstance();
    public static final List<String> ALL_COVERAGES = Arrays.asList("CC", "DC", "PA", "PS", "RT", "RP");
    public static final List<Integer> COVERAGE_TO_UNIQUE_ERR_IDX = Arrays.asList(0, 0, 1, 1, -1, -1);
    public static final int MAX_UNIQUE_ERR_IDX = 2;
    public static final int ERR_IDX_TO_STORE = 0;

    // TODO: move configs to ConfigConstants
    public static final int MAX_PACKET_TYPE_LEN = 6;
    public static final int CONFIG_MAX_SEED_IN_CORPUS = 1000;
    public static List<String> ALLOW_COVERAGES = Arrays.asList("CC", "DC");
    public static final boolean CONFIG_STORE_SEED_IN_CORPUS = true;

    private static Logger log = LoggerFactory.getLogger(P4CodeCovGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    JavaCodeCoverage controllerCoverage;
    Map<String, DeviceCodeCoverage> deviceCodeCovMap;
    Map<String, P4Coverage> devP4StmtCovMap;
    Map<String, P4Coverage> devP4ActionCovMap;
    // TODO: support multiple device
    Map<String, RuleTraceCoverage> ruleTraceCovMap;
    Map<String, RulePathCoverage> rulePathCovMap;
    Map<String, P4VulnType> vulnerableProtoFilePathMap;

    ScenarioSeedCorpora seedScenarioCorpora;

    FuzzP4PacketGuidance p4PacketGuidance;
    FuzzP4RuleGuidance p4RuleGuidance;

    JavaCodeCoverage localCtrlCov;
    Map<String, DeviceCodeCoverage> localDevCodeCovMap;
    Map<String, P4Coverage> localDevP4StmtCovMap;
    Map<String, P4Coverage> localDevP4ActionCovMap;
    Map<String, RuleTraceCoverage> localRuleTraceCovMap;
    Map<String, RulePathCoverage> localRulePathCovMap;
    Map<Integer, Long> numUniqueErrorMap;
    List<JavaCodeCoverage> uniqueErrorCtrlCovList;
    List<DeviceCodeCoverage> uniqueErrorDevCovList;

    private Random rand;

    private ReadWriteLock lock = new ReentrantReadWriteLock();

    public P4CodeCovGuidance() throws IllegalAccessException, InstantiationException, ClassNotFoundException,
            NoSuchMethodException, InvocationTargetException {
        rand = new Random();

        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.impl."
                + ConfigConstants.CONFIG_FUZZING_P4RULE_GUIDANCE);
        p4RuleGuidance = (FuzzP4RuleGuidance) clazz.getDeclaredConstructor().newInstance();

        Class p4packetClazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl."
                + ConfigConstants.CONFIG_FUZZING_P4PACKET_GUIDANCE);
        p4PacketGuidance = (FuzzP4PacketGuidance) p4packetClazz.getDeclaredConstructor().newInstance();

        if (p4PacketGuidance instanceof FP4PacketGuidance)
            ALLOW_COVERAGES = List.of("PA");
    }

    @Override
    public void init(Object o, String resultDirPath) throws IOException, InterruptedException {
        super.init(o, resultDirPath);
        controllerCoverage = new JavaCodeCoverage();
        deviceCodeCovMap = new HashMap<>();
        devP4StmtCovMap = new HashMap<>();
        devP4ActionCovMap = new HashMap<>();
        rulePathCovMap = new HashMap<>();
        ruleTraceCovMap = new HashMap<>();
        numUniqueErrorMap = new HashMap<>();
        uniqueErrorCtrlCovList = new ArrayList<>();
        uniqueErrorDevCovList = new ArrayList<>();
        vulnerableProtoFilePathMap = new HashMap<>();

        seedScenarioCorpora = new ScenarioSeedCorpora(this.coverageDirPath, MAX_PACKET_TYPE_LEN,
                CONFIG_MAX_SEED_IN_CORPUS);

        p4PacketGuidance.init();

        if (CommonUtil.isRuntimeConfigTestGenMode()) {
            ALLOW_COVERAGES = List.of("PS");
        }
    }

    @Override
    public boolean stop() {
        return super.stop();
    }

    @Override
    public @Nonnull CoverageUpdateInfo measureCoverage(FuzzScenario fuzzScenario, FuzzAction fuzzAction,
                                boolean isReset, boolean isEnd, boolean dumpCtrl)
            throws NumberFormatException, IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            // Just simply measure coverage
            super.measureCoverage(fuzzScenario, fuzzAction, isReset, isEnd, dumpCtrl);

            if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty() && !CommonUtil.isRuntimeConfigTestGenMode()) {
                List<DeviceCodeCoverage> coverages = P4Util.getTraceBits(isReset);
                log.info("Coverage of {} device(s) is measured", coverages.size());

                fuzzScenario.applyDeviceCodeCoverages(coverages);
            }

            // Measure P4 Coverage from fuzzAction
            if (fuzzAction == null) {
                for (FuzzAction action : fuzzScenario.getActionList()) {
                    // get p4test from the content
                    if (!action.getActionCmd().equals("p4test"))
                        continue;

                    FuzzActionContent content = action.getContent();
                    if (!(content instanceof FuzzActionP4TestContent))
                        continue;

                    fuzzAction = action;
                    break;
                }
            }

            if (fuzzAction != null) {
                FuzzActionContent content = fuzzAction.getContent();
                if (content instanceof FuzzActionP4TestContent) {
                    P4Testgen.TestCase testCase = ((FuzzActionP4TestContent) content).getTestCase();
                    // TODO: support multiple devices
                    String deviceId = ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID;

                    /* P4 Coverages (Statement, Action, and Rules) has updated right after mutation */
                    P4Coverage devP4StatementCov = new P4Coverage(deviceId,
                            testCase.getStmtCovBitmap().toByteArray(), testCase.getStmtCovSize());
                    fuzzScenario.applyP4StatementCoverages(List.of(devP4StatementCov));

                    P4Coverage devP4ActionCov = new P4Coverage(deviceId,
                            testCase.getActionCovBitmap().toByteArray(), testCase.getActionCovSize());
                    fuzzScenario.applyP4ActionCoverages(List.of(devP4ActionCov));

                    RuleTraceCoverage devRuleTraceCov = new RuleTraceCoverage(deviceId,
                            testCase.getEntitiesList());
                    fuzzScenario.applyRuleTraceCoverages(List.of(devRuleTraceCov));

                    RulePathCoverage devRulePathCov = new RulePathCoverage(deviceId, testCase);
                    fuzzScenario.applyRulePathCoverages(List.of(devRulePathCov));
                }
            }

            // Compare coverage of local and scenario.
            CoverageUpdateInfo reason = new CoverageUpdateInfo();
            if (!isEnd) {
                if (localCtrlCov == null) {
                    localCtrlCov = new JavaCodeCoverage();
                    localDevCodeCovMap = new HashMap<>();
                    localDevP4StmtCovMap = new HashMap<>();
                    localDevP4ActionCovMap = new HashMap<>();
                    localRuleTraceCovMap = new HashMap<>();
                    localRulePathCovMap = new HashMap<>();

                    // Move global to local
                    FuzzUtil.updateCoverages(localCtrlCov, controllerCoverage,
                            localDevCodeCovMap, deviceCodeCovMap,
                            localDevP4StmtCovMap, devP4StmtCovMap,
                            localDevP4ActionCovMap, devP4ActionCovMap,
                            localRuleTraceCovMap, ruleTraceCovMap,
                            localRulePathCovMap, rulePathCovMap);
                }

                // Move scenario to local
                reason.merge(FuzzUtil.updateCoverages(fuzzScenario,
                        dumpCtrl ? localCtrlCov : null,
                        localDevCodeCovMap, localDevP4StmtCovMap, localDevP4ActionCovMap,
                        localRuleTraceCovMap, localRulePathCovMap));

            } else {
                if (localCtrlCov != null) {
                    // Move local to global
                    FuzzUtil.updateCoverages(controllerCoverage, localCtrlCov,
                            deviceCodeCovMap, localDevCodeCovMap,
                            devP4StmtCovMap, localDevP4StmtCovMap,
                            devP4ActionCovMap, localDevP4ActionCovMap,
                            ruleTraceCovMap, localRuleTraceCovMap,
                            rulePathCovMap, localRulePathCovMap);
                }
                localCtrlCov = null;
                localDevCodeCovMap = null;
                localDevP4StmtCovMap = null;
                localDevP4ActionCovMap = null;
                localRuleTraceCovMap = null;
                localRulePathCovMap = null;
            }

            return reason;

        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void resetCoverage() throws IOException {
        super.resetCoverage();

        if (!ConfigConstants.CONFIG_P4_PIPELINE.isEmpty()) {
            HttpURLConnection conn = TestUtil.requestClearCov();
            if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300) {
                log.warn("Error in requesting clear coverage of devices");
            }
        }
    }

    @Nonnull
    public FuzzScenario getRandomScenario()
            throws IOException, EndFuzzException, StatusRuntimeException, SkipFuzzException {
        boolean isEqual = true;

        FuzzScenario seedScenario = getSeedScenario();
        FuzzScenario newScenario = FuzzScenario.copy(seedScenario);
        newScenario.setFuzzCnt(seedScenario.getFuzzCnt());

        newScenario.clearActionList();

        for (FuzzAction action : seedScenario.getActionList()) {
            /* While fuzzing scenario, do not fuzz subActions generated from parent action. */
            if (action.isSubAction())
                continue;

            List<FuzzAction> newActionList = FuzzAction.fuzz(action);
            newScenario.addAction(newActionList);
            if (newActionList.size() > 0 && !newActionList.get(0).equals(action))
                isEqual = false;
        }

        // AFL generates the same input in start stage.
        if (!isEqual) {
            newScenario.incFuzzCnt();
            newScenario.setFuzzed(true);
        }

        return newScenario;
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, EndFuzzException, StatusRuntimeException, SkipFuzzException {
        boolean isEqual = true;

        // Skip scenarios (copied for initial stability)
        if (!scenario.canFuzz())
            return null;

        FuzzScenario seedScenario = getSeedScenario();
        FuzzScenario newScenario = FuzzScenario.copy(seedScenario);
        newScenario.setFuzzCnt(scenario.getFuzzCnt());

        newScenario.clearActionList();

        for (FuzzAction action : scenario.getActionList()) {
            /* While fuzzing scenario, do not fuzz subActions generated from parent action. */
            if (action.isSubAction())
                continue;

            List<FuzzAction> newActionList = FuzzAction.fuzz(action);
            newScenario.addAction(newActionList);
            if (newActionList.size() > 0 && !newActionList.get(0).equals(action))
                isEqual = false;
        }

        // AFL generates the same input in start stage.
        if (!isEqual) {
            newScenario.incFuzzCnt();
            newScenario.setFuzzed(true);
        }

        return newScenario;
    }

    @Override
    public ActionFuzzStatus continueActionFuzzing(FuzzScenario fuzzScenario, FuzzAction action) {
        if (!action.getActionCmd().equals("dp-verify-rule"))
            return ActionFuzzStatus.UNSUPPORTED;

        /* Init of action fuzzing */
        if (fuzzScenario != null) {
            int numFuzzPackets = ConfigConstants.CONFIG_P4_FUZZ_PACKET_CNT;
            p4PacketGuidance.initFuzzActionCnt(numFuzzPackets, this.startTime, this.execDuration);
        }

        return p4PacketGuidance.continueActionFuzzing();
    }

    @Override
    public boolean isContinuous() {
        return p4PacketGuidance.isContinuous();
    }

    @Override
    public @Nullable FuzzAction mutateAction(FuzzAction action, FuzzScenario scenario)
            throws SkipFuzzException, EndFuzzException {
        String actionCmd = action.getActionCmd();

        // Now, we do not mutate control-plane subActions, separately.
        // Scenario mutation will mutate parentAction (p4fuzz)
        if (!actionCmd.equals("dp-verify-rule")) {
            return null;
        }

        FuzzScenario seedScenario = getSeedScenario(scenario);
        if (seedScenario != null) {
            for (FuzzAction seedAction : seedScenario.getActionList()) {
                if (seedAction.getActionCmd().equals("dp-verify-rule"))
                    return getRandomAction(seedAction);
            }
        }

        return getRandomAction(action);
    }

    @Override
    public @Nullable FuzzAction getRandomAction(FuzzAction action)
            throws EndFuzzException, SkipFuzzException {
        String actionCmd = action.getActionCmd();

        // Now, we do not mutate control-plane subActions, separately.
        // Scenario mutation will mutate parentAction (p4fuzz)
        if (actionCmd.equals("add-rule") ||
                actionCmd.equals("cp-verify-rule")) {
            return null;
        }

        FuzzAction newAction = FuzzAction.copy(action);

        FuzzActionContent content = action.getContent();
        if (!(content instanceof FuzzActionP4TestContent))
            return newAction;


        Instant startMutateTime = Instant.now();

        // copy content from the seed
        FuzzActionP4TestContent newContent = (FuzzActionP4TestContent) content.deepCopy();

        // Get full TestCase (it can be whole TestCase (p4test or dp-verify-rule)
        P4Testgen.TestCase prevTest = newContent.getTestCase();

        P4Testgen.TestCase newRuleTest;

        boolean isPacketMutant = false;
        if (actionCmd.equals("dp-verify-rule") || !action.isFuzzed()) {
            /* fuzz from getRandomAction() directly or init p4test action */
            newRuleTest = p4PacketGuidance.getRandomP4Packet(prevTest);
            isPacketMutant = true;

        } else {
            /* fuzz from getRandomScenario() */
            newRuleTest = p4RuleGuidance.getRandomP4Entities(prevTest);
        }

        if (ConfigConstants.CONFIG_SKIP_P4_KNOWN_BUGS) {
            P4KnownBugType bugType = P4Util.getP4KnownBugType(newRuleTest);
            if (!bugType.equals(P4KnownBugType.NONE)) {
                // generate once again.
                log.warn("{} is generated", bugType);
                return newAction;
            }
        }

        P4VulnType vulnType = P4Util.isVulnerable(newRuleTest);
        if (!vulnType.equals(P4VulnType.NONE)) {
            String ruleFilePath = CommonUtil.createRuleProtoFilePath(false);
            try (FileWriter fileWriter = new FileWriter(ruleFilePath)) {
                fileWriter.write(newRuleTest.toString());
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
            vulnerableProtoFilePathMap.put(ruleFilePath, vulnType);
        }
        newAction.setP4VulnType(vulnType);

        newAction.setPacketType(P4Util.genPacketType(newRuleTest));

        if (newRuleTest.getUnsupported() > 0)
            newAction.setUnsupported();


        newContent.setTestCase(newRuleTest);
        newContent.getContent().addProperty("P4Testgen",
                Base64.encodeBase64String(newRuleTest.toByteArray()));

        // logging, only if action is parentAction
        if (!isPacketMutant) {
            if (prevTest.getEntitiesCount() != newRuleTest.getEntitiesCount()) {
                log.debug("change P4 rule counts {} -> {}",
                        prevTest.getEntitiesCount(),
                        newRuleTest.getEntitiesCount());
            } else {
                Patch<String> patch = DiffUtils.diff(Arrays.asList(prevTest.toString().split("\\r?\\n")),
                        Arrays.asList(newRuleTest.toString().split("\\r?\\n")));

                StringBuffer sb = new StringBuffer();
                for (AbstractDelta<String> delta : patch.getDeltas()) {
                    sb.append("\n");
                    sb.append(delta);
                }

                log.debug("P4 rule is changed:{}", sb);
            }
        }

        // update content
        newAction.setContent(newContent);

        Instant endMutateTime = Instant.now();
        addActionResultByCmd(actionCmd + "-mutate",
                Duration.between(startMutateTime, endMutateTime).toMillis());

        return newAction;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        super.feedbackResult(fuzzScenario);
        log.info("Feedback");

        // We already stored copied scenario that cannot fuzz.
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        // Update coverages in guidance
        reason.merge(FuzzUtil.updateCoverages(fuzzScenario, controllerCoverage,
                deviceCodeCovMap, devP4StmtCovMap, devP4ActionCovMap,
                ruleTraceCovMap, rulePathCovMap));

        if (reason.isUpdated()) {
            if (fuzzScenario.canFuzz()) {
                addSeed(fuzzScenario, reason);
            }
        }

        // Increment error when the scenario has not been stored (e.g. by action fuzzing)
        if (fuzzScenario.doesStoreSeed(reason) && fuzzScenario.isError()) {
            this.incErrors();
            if (reason.isUpdated()) {
                this.incUniqueErrors();
                this.incUniqueErrorsByCovMetrics(fuzzScenario, reason);
            }
        }

        return true;
    }

    @Override
    public void incUniqueErrorsByCovMetrics(FuzzScenario scenario, CoverageUpdateInfo reason) {
        Set<String> covNameSet = reason.getAllUpdatedCoverageNames();
        boolean[] isChecked = new boolean[MAX_UNIQUE_ERR_IDX + 1];
        for (String covName : covNameSet) {
            assert covName.length() >= 2;
            String covType = covName.substring(0, 2);
            int covIdx = ALL_COVERAGES.indexOf(covType);

            // skip if covType is unknown or not used for error uniqueness
            if (covIdx < 0 || COVERAGE_TO_UNIQUE_ERR_IDX.get(covIdx) < 0)
                continue;

            int errIdx = COVERAGE_TO_UNIQUE_ERR_IDX.get(covIdx);
            if (!isChecked[errIdx]) {
                isChecked[errIdx] = true;
                long uniqueErrIdx = numUniqueErrorMap.getOrDefault(errIdx, 0L);
                numUniqueErrorMap.put(errIdx, uniqueErrIdx + 1);
                /* If input finds new path of covIdx, store coverages */
                if (errIdx == ERR_IDX_TO_STORE) {
                    // Get coverages of scenario
                    uniqueErrorCtrlCovList.add(scenario.getCodeCoverage().deepCopy());
                    DeviceCodeCoverage scenarioDevCov = null;
                    for (DeviceCodeCoverage cov : scenario.getDeviceCodeCoverages()) {
                        if (scenarioDevCov == null)
                            scenarioDevCov = cov.deepCopy();
                        else
                            scenarioDevCov.updateCoverage(cov);
                    }
                    uniqueErrorDevCovList.add(scenarioDevCov);
                }
            }

            if (!isChecked[MAX_UNIQUE_ERR_IDX]) {
                isChecked[MAX_UNIQUE_ERR_IDX] = true;
                numUniqueErrorMap.put(MAX_UNIQUE_ERR_IDX, numUniqueErrorMap.getOrDefault(MAX_UNIQUE_ERR_IDX, 0L) + 1);
            }
        }
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        return false;
    }

    @Override
    public String getStatsHeader() {
        StringBuilder sb = new StringBuilder();
        sb.append(JavaCodeCoverage.getStatsHeader());
        sb.append(", ");
        sb.append(DeviceCodeCoverage.getStatsHeader());
        sb.append(", ");
        sb.append(P4Coverage.getStatsHeader());
        sb.append(", err, uniqErr (Code, P4, Code+P4, ALL)");
        return sb.toString();
    }

    @Override
    public String getStatsString() {
        StringBuilder sb = new StringBuilder();
        sb.append(controllerCoverage.getStatsString());
        deviceCodeCovMap.values().forEach(k -> {
            sb.append(", ");
            sb.append(k.getStatsString(false));
        });

        sb.append(", PS, ");
        if (devP4StmtCovMap.isEmpty()) {
            sb.append(0).append(", ").append(0);
        } else {
            devP4StmtCovMap.values().forEach(k -> {
                sb.append(k.getStatsString(false));
            });
        }

        sb.append(", PA, ");
        if (devP4ActionCovMap.isEmpty()) {
            sb.append(0).append(", ").append(0);
        } else {
            devP4ActionCovMap.values().forEach(k -> {
                sb.append(k.getStatsString(false));
            });
        }

        // set stat for rule trace
        sb.append(", RT, ");
        if (ruleTraceCovMap.isEmpty()) {
            sb.append(0).append(", ").append(0);
        } else {
            Integer hitRules = ruleTraceCovMap.values().stream()
                    .map(RuleTraceCoverage::getHitCount)
                    .reduce(0, Integer::sum);

            Integer totalRules = ruleTraceCovMap.values().stream()
                    .map(RuleTraceCoverage::getMapSize)
                    .reduce(0, Integer::sum);
            sb.append(hitRules).append(", ").append(totalRules);
        }

        // set stat for rule path
        sb.append(", RP[MAX/SUM], ");
        if (rulePathCovMap.isEmpty()) {
            sb.append(0).append(", ").append(0);
        } else {
            Integer maxPaths = rulePathCovMap.values().stream()
                    .map(RulePathCoverage::getPathCount)
                    .mapToInt(v -> v)
                    .max().orElseThrow(NoSuchElementException::new);

            Integer sumPaths = rulePathCovMap.values().stream()
                    .map(RulePathCoverage::getPathCount)
                    .reduce(0, Integer::sum);

            sb.append(maxPaths).append(", ").append(sumPaths);
        }
        sb.append(", ").append(seedScenarioCorpora.statString(P4CodeCovGuidance.ALL_COVERAGES));
        sb.append(", ").append(numErrors);
        for (int i = 0; i <= MAX_UNIQUE_ERR_IDX; i++) {
            sb.append(", ").append(numUniqueErrorMap.getOrDefault(i, 0L));
        }
        sb.append(", ").append(numUniqueErrors);
        return sb.toString();
    }

    @Override
    public String getStatsString(FuzzScenario curScenario) {
        Lock readLock = lock.writeLock();
        readLock.lock();
        try {
            if (localCtrlCov == null)
                return null;

            StringBuilder sb = new StringBuilder();
            FuzzUtil.updateCoverages(curScenario, localCtrlCov, localDevCodeCovMap,
                    localDevP4StmtCovMap, localDevP4ActionCovMap,
                    localRuleTraceCovMap, localRulePathCovMap);
            sb.append(localCtrlCov.getStatsString());
            localDevCodeCovMap.values().forEach(k -> {
                sb.append(", ");
                sb.append(k.getStatsString(false));
            });

            sb.append(", PS, ");
            if (localDevP4StmtCovMap.isEmpty()) {
                sb.append(0).append(", ").append(0);
            } else {
                localDevP4StmtCovMap.values().forEach(k -> {
                    sb.append(k.getStatsString(false));
                });
            }

            sb.append(", PA, ");
            if (localDevP4ActionCovMap.isEmpty()) {
                sb.append(0).append(", ").append(0);
            } else {
                localDevP4ActionCovMap.values().forEach(k -> {
                    sb.append(k.getStatsString(false));
                });
            }

            // set stat for rule trace
            sb.append(", RT, ");
            if (localRuleTraceCovMap.isEmpty()) {
                sb.append(0).append(", ").append(0);
            } else {
                Integer hitRules = localRuleTraceCovMap.values().stream()
                        .map(RuleTraceCoverage::getHitCount)
                        .reduce(0, Integer::sum);

                Integer totalRules = localRuleTraceCovMap.values().stream()
                        .map(RuleTraceCoverage::getMapSize)
                        .reduce(0, Integer::sum);
                sb.append(hitRules).append(", ").append(totalRules);
            }

            // set stat for rule path
            sb.append(", RP[MAX/SUM], ");
            if (localRulePathCovMap.isEmpty()) {
                sb.append(0).append(", ").append(0);
            } else {
                Integer maxPaths = localRulePathCovMap.values().stream()
                        .map(RulePathCoverage::getPathCount)
                        .mapToInt(v -> v)
                        .max().orElseThrow(NoSuchElementException::new);

                Integer sumPaths = localRulePathCovMap.values().stream()
                        .map(RulePathCoverage::getPathCount)
                        .reduce(0, Integer::sum);

                sb.append(maxPaths).append(", ").append(sumPaths);
            }

            sb.append(", ").append(seedScenarioCorpora.statString(P4CodeCovGuidance.ALL_COVERAGES));
            sb.append(", ").append(numErrors);
            for (int i = 0; i <= MAX_UNIQUE_ERR_IDX; i++) {
                sb.append(", ").append(numUniqueErrorMap.getOrDefault(i, 0L));
            }
            sb.append(", ").append(numUniqueErrors);
            return sb.toString();

        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void storeMetadata(String logDir) {
        try {
            File failProtoFile = new File(logDir + File.separator + "fail_proto.txt");
            PrintStream resultOut = new PrintStream(failProtoFile);
            p4PacketGuidance.getFailedTestgenProtoFilePathList().forEach(resultOut::println);
            p4RuleGuidance.getFailedTestgenProtoFilePathList().forEach(resultOut::println);
            resultOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (!vulnerableProtoFilePathMap.isEmpty()) {
            try {
                File vulnProtoFile = new File(logDir + File.separator + "vuln_proto.out");
                PrintStream resultOut = new PrintStream(vulnProtoFile);
                vulnerableProtoFilePathMap.forEach((k, v) -> resultOut.println(P4Util.getVulnTypeStr(v) + ":" + k));
                resultOut.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (!CommonUtil.isRuntimeConfigTestGenMode()) {
            try {
                File covFile = new File(logDir + File.separator + ONOSUtil.ONOSCovOutputFile);
                PrintStream covOut = new PrintStream(covFile);
                controllerCoverage.analyze(covOut);
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
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {}

    @Override
    public boolean addSeed(FuzzScenario fuzzScenario, CoverageUpdateInfo reason) {
        if (!reason.isUpdated() || !fuzzScenario.doesStoreSeed(reason))
            return false;

        if (fuzzScenario.isFuzzed() && !CONFIG_STORE_SEED_IN_CORPUS)
            return false;

        FuzzAction errAction = fuzzScenario.getErrorAction();
        if (!ConfigConstants.CONFIG_STORE_ADD_RULE_ERROR_IN_CORPUS &&
                errAction != null && errAction.getActionCmd().equals("add-rule"))
            return false;

        if (!ConfigConstants.CONFIG_STORE_CP_VERIFY_RULE_ERROR_IN_CORPUS &&
                errAction != null && errAction.getActionCmd().equals("cp-verify-rule"))
            return false;

        // Get firstKey
        Set<String> covNameSet = reason.getAllUpdatedCoverageNames();

        // Get secondKey and thirdKey
        P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(fuzzScenario);
        String [] secondKeys = new String[2];
        final int thirdKey;
        int thirdKeyBit = 0;       // [PKT_OUT][DROP][PKT_IN]
        if (testCase != null) {
            secondKeys[0] = P4Util.genHashCode(testCase.getEntitiesList());
            secondKeys[1] = P4Util.genHashCodeFromMatched(testCase.getEntitiesList());
            thirdKeyBit = P4Util.genPacketType(testCase);
        } else {
            secondKeys[0] = "SINGLE";
            secondKeys[1] = "SINGLE";
        }
        thirdKey = thirdKeyBit;

        SeedScenario seedScenario = new SeedScenario(fuzzScenario);
        boolean isStored = false;
        for (String covName : covNameSet) {
            assert covName.length() >= 2;
            String covType = covName.substring(0, 2);
            if (!P4CodeCovGuidance.ALLOW_COVERAGES.contains(covType))
                continue;

            if (seedScenarioCorpora.putSeed(covName, secondKeys, thirdKey, seedScenario)) {
                isStored = true;
                Coverage coverage = reason.getCoverage(covName);
                if (ConfigConstants.CONFIG_STORE_COVERAGE_DATA && coverage.hasBitmap()) {
                    // It can create too many files
                    CommonUtil.mkdir(this.coverageDirPath + File.separator + covName);
                    coverage.storeCoverageMap(this.coverageDirPath + File.separator + covName +
                            File.separator + seedScenario.getUuid());
                }
            }
        }

        if (isStored) {
            // Store interesting mutant scenarios
            fuzzScenario.logScenario(this.interestingDirPath + File.separator +
                    seedScenario.getUuid() + "-" + reason);
        }
        return isStored;
    }

    private FuzzScenario getSeedScenario() {
        return seedScenarioCorpora.getNextSeed(null).getScenario();
    }

    private @Nullable FuzzScenario getSeedScenario(FuzzScenario from) {
        // Get secondKey
        P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(from);
        String secondKey = "SINGLE";
        if (testCase != null) {
            secondKey = P4Util.genHashCode(testCase.getEntitiesList());
        }

        // Get seed with fixed secondKey
        SeedScenario seedScenario = seedScenarioCorpora.getNextSeed(secondKey);
        if (seedScenario == null)
            return null;

        // Calculate secondKey of seed
        FuzzScenario scenario = seedScenario.getScenario();
        testCase = P4Util.getP4TestgenFromScenario(scenario);
        String newSecondKey = "SINGLE";
        if (testCase != null) {
            newSecondKey = P4Util.genHashCode(testCase.getEntitiesList());
        }

        if (ConfigConstants.CONFIG_P4_SEED_CORPUS_POLICY.equals(P4SeedCorpusPolicy.UNIQUE_RULE) ||
                ConfigConstants.CONFIG_P4_SEED_CORPUS_POLICY.equals(P4SeedCorpusPolicy.UNIQUE_RULE_AND_PACKET)) {
            if (!secondKey.equals(newSecondKey))
                return null;
        }

        return seedScenario.getScenario();
    }

    @Override
    public boolean preprocess(FuzzScenario scenario) throws IOException {
        // TODO: support multiple devices
        String deviceId = ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID;
        FuzzAction p4Action = P4Util.getP4TestgenActionFromScenario(scenario);

        if (p4Action == null) {
            log.warn("scenario does not have P4 Testcase");
            return false;
        }

        FuzzActionP4TestContent testContent = (FuzzActionP4TestContent) p4Action.getContent();
        P4Testgen.TestCase testCase = testContent.getTestCase();

        int pid = TestUtil.getTestAgentPid();
        if (pid <= 0)
            return false;

        /* (1) Parse existing rules */
        P4Testgen.TestCase testCaseOnSwitch = TestUtil.requestDumpRule(deviceId);
        if (testCaseOnSwitch == null) {
            log.error("fail to get rules");
            return false;
        }

        List<Entity_Fuzz> existingRules = testCaseOnSwitch.getEntitiesList();
        if (existingRules.isEmpty()) {
            log.warn("Empty entities");
            return false;
        }
        log.debug("{} existing entities", existingRules.size());

        /* (2) Collect rules under test */
        List<Entity_Fuzz> rulesUnderTest = P4Util.getEntities(testCase.getEntitiesList(),
                Optional.empty(), Optional.of(true));
        log.debug("{} entities under test", rulesUnderTest.size());

        /* (1) + (2) */
        P4Testgen.TestCase.Builder ruleBuilder = P4Testgen.TestCase.newBuilder(testCase);
        ruleBuilder.clearEntities();
        ruleBuilder.addAllEntities(rulesUnderTest);
        ruleBuilder.addAllEntities(existingRules);
        P4Testgen.TestCase updatedTestCase = ruleBuilder.build();

        // Get P4 Coverage and expected output
        P4CoverageReplyWithError covReply = p4UtilInstance.recordP4Testgen(deviceId, updatedTestCase, 1);
        if (covReply.isError()) {
            log.error("Cannot execute P4CE: {}", covReply.getErrorType().toString());
            return false;
        }

        /*
         * NOTE: Assuming that the output port of preprocessed testCase
         *       is always within a valid range of ports.
         */
        P4Testgen.TestCase newRuleTest = covReply.getResp().getTestCase();
        FuzzActionP4TestContent newContent = testContent.deepCopy();
        newContent.setTestCase(newRuleTest);
        newContent.getContent().addProperty("P4Testgen",
                Base64.encodeBase64String(newRuleTest.toByteArray()));

        // update content
        FuzzAction newAction = FuzzAction.copy(p4Action);
        newAction.setContent(newContent);
        // seed content should be updated to apply default rules
        newAction.setSeedContent(newContent);
        newAction.setPacketType(P4Util.genPacketType(newRuleTest));
        scenario.replaceAction(p4Action, newAction);

        log.debug("successfully preprocessed: {}", scenario.getName());

        return true;
    }
}
