package edu.purdue.cs.pursec.ifuzzer.cli;

import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand.FuzzCandidates;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.result.FuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import io.grpc.StatusRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.globalTopoGuidance;
import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.scenarioGuidance;

@Command(name = "testgen", mixinStandardHelpOptions = true)
public class TestGenCommand implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(TestGenCommand.class);
    private static String testGenDirPath;
    private static String testGenFilesPath;
    public static PrintStream testGenStatOut;

    public LocalDateTime startFuzzDate;

    @ParentCommand
    CliCommands parent;

    @Option(names = "-t", description = "execution time", defaultValue = "PT0S")
    Duration execDuration;

    @Option(names = "-s", description = "store gen file(s)", defaultValue = "false")
    boolean doesStore;

    @Parameters(index= "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = FuzzCandidates.class)
    String[] fileNames;

    @Override
    public void run() {
        CommonUtil.saveRuntimeConfig();
        CommonUtil.setRuntimeConfigTestGenMode(true);

        List<File> scenarioFiles;
        try {
            scenarioFiles = CommonUtil.readAllFiles(fileNames, IFuzzer.scenarioPath);
        } catch (IOException e) {
            parent.out.println("Error: " + e.getMessage());
            return;
        }

        String curDate = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

        testGenDirPath = IFuzzer.scenarioPath + File.separator + curDate + "-testgen";
        File testGenDir = new File(testGenDirPath);
        if (!testGenDir.exists()) {
            if (!testGenDir.mkdir()) {
                System.err.printf("Cannot create %s\n", testGenDirPath);
                System.exit(2);
            }
        }

        testGenFilesPath = testGenDirPath + File.separator + "tests";
        File testGenFiles = new File(testGenFilesPath);
        if (!testGenFiles.exists()) {
            if (!testGenFiles.mkdir()) {
                System.err.printf("Cannot create %s\n", testGenFilesPath);
                System.exit(2);
            }
        }

        try {
            File statFile = new File(testGenDirPath + File.separator + "stat.out");
            testGenStatOut = new PrintStream(statFile);
            testGenStatOut.println(scenarioGuidance.getStatsHeader());
            testGenStatOut.flush();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(2);
        }

        /* initialize guidance */
        try {
            parent.scenarioStore.init();
            scenarioGuidance.init(parent.configTopoGraph, testGenDirPath);
            globalTopoGuidance.init(parent.topoGraph);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }

        /* read scenarios from given files */
        Queue<FuzzScenario> scenarioList = new LinkedList<>();
        for (File scenarioFile : scenarioFiles) {
            try {
                JsonObject scenarioJson = TestUtil.fromJson(new FileReader(scenarioFile));

                if (scenarioJson != null) {
                    FuzzScenario scenario = new FuzzScenario(scenarioJson);
                    boolean isPreprocessed = scenarioGuidance.preprocess(scenario);

                    if (!isPreprocessed) {
                        parent.out.println("** Run replay first to execute test-agent!!! **");
                        return;
                    }
                    scenarioList.add(scenario);
                }

            } catch (Exception e) {
                e.printStackTrace();
                parent.out.printf("Error while reading %s: %s\n", scenarioFile, e.getMessage());
            }
        }


        FuzzResult totalResult = new FuzzResult();
        FuzzResult fuzzResult = new FuzzResult();
        LocalDateTime startDate = LocalDateTime.now();
        startFuzzDate = null;
        boolean isFuzzing = false;
        long genTestCnt = 0;

        /** Main Loop: Execute scenarios **/
        FuzzScenario scenario = null;
        while (!scenarioList.isEmpty()) {
            scenario = scenarioList.poll();

            // Start measure time
            if (scenario.getFuzzCnt() == 1 && !isFuzzing) {
                startFuzzDate = LocalDateTime.now();
                parent.scenarioStore.setStartFuzzing(startFuzzDate, execDuration);
                scenarioGuidance.setStartFuzzing(startFuzzDate, execDuration);
                isFuzzing = true;
            }

            // Measure P4 coverages (scenario-level)
            try {
                scenarioGuidance.measureCoverage(scenario, null,
                        false, true, false);
                scenarioGuidance.feedbackResult(scenario);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            int skipped = 0;
            while (true) {
                try {
                    if (scenario.stopFuzz()) {
                        scenarioList.clear();
                        break;
                    }

                    // Run seed continuously.
                    if (!scenarioList.isEmpty())
                        break;

                    if (startFuzzDate == null || Duration.between(startFuzzDate, LocalDateTime.now())
                            .compareTo(execDuration) < 0) {

                        if (scenario.isFuzzed()) {
                            // Find the action that can be fuzzed
                            FuzzAction actionToFuzz = null;
                            for (FuzzAction action : scenario.getActionList()) {
                                if (action.getActionCmd().equals("dp-verify-rule")) {
                                    actionToFuzz = action;
                                    break;
                                }
                            }

                            if (isFuzzing) {
                                testGenStatOut.println(scenarioGuidance.getStatsString() + ", " + (genTestCnt + 1));
                                testGenStatOut.flush();
                            }

                            if (actionToFuzz == null) {
                                // No action to fuzz
                                // (1) Store current scenario
                                genTestCnt++;
                                if (doesStore) {
                                    String fileName = LocalDateTime.now()
                                            .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
                                    scenario.logScenario(testGenFilesPath + File.separator + fileName);
                                }
                            }

                            boolean isFuzzedAction = false;
                            while (actionToFuzz != null) {
                                FuzzScenario scenarioWithMutant = scenario;
                                if (isFuzzedAction) {
                                    scenarioWithMutant = FuzzScenario.copy(scenario, actionToFuzz);
                                }

                                // (1) Store current scenario
                                genTestCnt++;
                                if (doesStore) {
                                    String fileName = LocalDateTime.now()
                                            .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
                                    scenarioWithMutant.logScenario(testGenFilesPath + File.separator + fileName);
                                }

                                // (2) Check action-level fuzzing
                                ActionFuzzStatus actionFuzzStatus = scenarioGuidance
                                        .continueActionFuzzing(isFuzzedAction ? null : scenario, actionToFuzz);

                                switch (actionFuzzStatus) {
                                    case PROCESSING:
                                    {
                                        try {
                                            // (3) Measure P4 coverages (action-level)
                                            CoverageUpdateInfo findNewPathReasons = scenarioGuidance.measureCoverage(scenario,
                                                    isFuzzedAction ? actionToFuzz : null,
                                                    false, false, false);

                                            if (findNewPathReasons.isUpdated()) {
                                                scenarioGuidance.addSeed(scenarioWithMutant, findNewPathReasons);
                                            }

                                            // Get new action to run again
                                            actionToFuzz = scenarioGuidance.mutateAction(actionToFuzz, scenario);
                                            isFuzzedAction = true;

                                        } catch (IOException e) {
                                            e.printStackTrace();
                                        } catch (EndFuzzException | SkipFuzzException ignore) {
                                            // Stop action-level fuzzing
                                        }
                                        break;
                                    }

                                    case UNSUPPORTED:
                                    case DONE:
                                        actionToFuzz = null;
                                        break;
                                }
                            }
                        }

                        scenarioList.add(scenarioGuidance.getRandomScenario());      // FUZZ SCENARIO

                    } else if (Duration.between(startFuzzDate, LocalDateTime.now()).compareTo(execDuration) >= 0) {
                        // Stop Fuzz!
                        scenarioList.clear();
                        break;
                    }

                } catch (IOException | StatusRuntimeException e) {
                    e.printStackTrace();

                } catch (SkipFuzzException e) {
                    if (++skipped > ConfigConstants.CONFIG_MAX_FUZZ_RETRY_CNT) {
                        // stop fuzz
                        log.warn("Stop fuzz by exception");
                        scenarioList.clear();
                    } else {
                        log.warn("Get another random input");
                        continue;
                    }

                } catch (JsonSyntaxException e) {
                    scenario.incFuzzCnt();
                    totalResult.addResult(e);
                    if (scenario.isFuzzed())
                        fuzzResult.addResult(e);
                    continue;

                } catch (EndFuzzException | GuidanceException e) {
                    log.warn("Stop fuzz by exception", e);
                    // stop fuzz
                    scenarioList.clear();
                }

                break;
            }
        }
        scenarioGuidance.stop();

        if (scenario != null)
            parent.scenarioStore.revertAllConfigTopoOperations(scenario);

        String totalResultStr = "[TOTAL] Test Cnt: " + genTestCnt + " (" +
                Duration.between(startDate, LocalDateTime.now()).toString() + ")";
        parent.out.println(totalResultStr);

        scenarioGuidance.storeMetadata(testGenDirPath);
        try {
            File resultFile = new File(testGenDirPath + File.separator + "result.out");
            PrintStream resultOut = new PrintStream(resultFile);
            resultOut.println(totalResultStr);
            String resultStr = scenarioGuidance.getResultsString();
            if (resultStr != null && !resultStr.isEmpty())
                resultOut.println(resultStr);

            if (testGenStatOut != null) {
                testGenStatOut.println(scenarioGuidance.getStatsString() + ", " + genTestCnt);
                testGenStatOut.flush();
                testGenStatOut.close();
            }
            resultOut.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        CommonUtil.restoreRuntimeConfig();
    }
}
