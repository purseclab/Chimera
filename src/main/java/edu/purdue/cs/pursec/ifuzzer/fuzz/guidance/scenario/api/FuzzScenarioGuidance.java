package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.ActionFuzzStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.CoverageUpdateInfo;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.result.ScenarioFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import io.grpc.StatusRuntimeException;
import org.jacoco.core.tools.ExecFileLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;

public abstract class FuzzScenarioGuidance {

    protected static Logger log = LoggerFactory.getLogger(FuzzScenarioGuidance.class);

    // stats
    protected boolean isInit = false;
    protected String resultDirPath;
    protected String failedDirPath;
    protected String interestingDirPath;
    protected String coverageDirPath;
    protected String uniqueErrPath;
    protected LocalDateTime startTime;
    protected Duration execDuration;

    private ScenarioFuzzResult fuzzResult;
    private boolean startFuzzing = false;

    public long numErrors;
    public long numUniqueErrors;

    /** abstract methods **/
    @Deprecated
    public abstract FuzzScenario getRandomScenario(FuzzScenario fuzzScenario)
            throws IOException, EndFuzzException, SkipFuzzException;
    @Nullable
    public abstract FuzzAction getRandomAction(FuzzAction action)
            throws IOException, EndFuzzException, StatusRuntimeException, SkipFuzzException;
    public abstract boolean doesRequireLogging(FuzzScenario scenario);
    public abstract String getStatsHeader();
    public abstract String getStatsString();
    public abstract void storeMetadata(String logDir);
    public abstract void addSeeds(Collection<FuzzScenario> fuzzScenarios);
    public boolean addSeed(FuzzScenario fuzzScenario, CoverageUpdateInfo reason) {
        return false;
    }

    public FuzzAction mutateAction(FuzzAction action, FuzzScenario scenario)
            throws SkipFuzzException, IOException, EndFuzzException {
        return getRandomAction(action);
    }

    public boolean preprocess(FuzzScenario scenario) throws IOException {
        return true;
    }

    /** concrete methods **/
    public void init(Object o, String resultDirPath) throws IOException, InterruptedException {
        this.resultDirPath = resultDirPath;
        CommonUtil.mkdir(this.resultDirPath);
        this.failedDirPath = resultDirPath + File.separator + "failure";
        CommonUtil.mkdir(this.failedDirPath);
        this.interestingDirPath = resultDirPath + File.separator + "interesting";
        CommonUtil.mkdir(this.interestingDirPath);
        this.coverageDirPath = resultDirPath + File.separator + "coverage";
        CommonUtil.mkdir(this.coverageDirPath);
        this.uniqueErrPath = resultDirPath + File.separator + "unique_err";
        CommonUtil.mkdir(this.uniqueErrPath);

        fuzzResult = new ScenarioFuzzResult();
        startFuzzing = false;
        isInit = true;
        startTime = null;
        numErrors = numUniqueErrors = 0;
    }

    public boolean stop() {
        isInit = false;
        return true;
    }

    public FuzzScenario getRandomScenario() throws IOException, EndFuzzException, SkipFuzzException {
        /* NOTE: implement override method! */
        return null;
    }

    public void setStartFuzzing(LocalDateTime startTime, Duration execDuration) {
        this.startTime = startTime;
        this.execDuration = execDuration;
        this.startFuzzing = true;
    }

    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        return fuzzResult.addScenarioResult(fuzzScenario);
    }

    public boolean addActionResultByCmd(String actionCmd, long durationMillis) {
        if (!ConfigConstants.CONFIG_STORE_INITIAL_TESTS_IN_RESULTS && !startFuzzing)
            return false;

        return fuzzResult.addActionResultByCmd(actionCmd, durationMillis);
    }

    public boolean addActionResult(FuzzAction fuzzAction) {
        return fuzzResult.addActionResult(fuzzAction);
    }

    public String getResultsString() {
        return fuzzResult.getResultsString();
    }

    public String getStatsString(FuzzScenario curScenario) {
        return this.getStatsString();
    }

    /*
     * measureCoverage(): measure guidance-specific coverage.
     * It returns whether changes exist in scenario coverage by default.
     * By overriding, it can return changes between scenario and global tracebits
     * (e.g., SingleP4RuleGuidance).
     */
    public @Nonnull CoverageUpdateInfo measureCoverage(FuzzScenario fuzzScenario, FuzzAction fuzzAction,
                                                       boolean isReset, boolean isEnd, boolean dumpCtrl)
            throws NumberFormatException, IOException {
        CoverageUpdateInfo reason = new CoverageUpdateInfo();

        if (dumpCtrl) {
            // dump coverage
            ExecFileLoader loader = ONOSUtil.dumpCoverage(isReset);

            if (fuzzScenario.applyCodeCoverage(loader)) {
                reason.hasUpdated("CC", fuzzScenario.getCodeCoverage());
            }
        }

        return reason;
    }

    public void resetCoverage() throws IOException {
        // reset coverage
        ONOSUtil.dumpCoverage(true);
    }

    public ActionFuzzStatus continueActionFuzzing(FuzzScenario fuzzScenario, FuzzAction action) {
        return ActionFuzzStatus.UNSUPPORTED;
    }

    public boolean isContinuous() {
        return false;
    }

    public void incErrors() {
        this.numErrors ++;
    }

    public void incUniqueErrors() {
        this.numUniqueErrors ++;
    }

    public void incUniqueErrorsByCovMetrics(FuzzScenario scenario, CoverageUpdateInfo reason) {
    }
}
