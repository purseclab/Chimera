package edu.purdue.cs.pursec.ifuzzer.cli;


import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.result.FuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.ChimeraTTF;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import io.grpc.StatusRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.*;

@Command(name = "fuzz", mixinStandardHelpOptions = true)
public class FuzzCommand implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(FuzzCommand.class);
    @ParentCommand
    CliCommands parent;

    public FuzzCommand() {}

    @Option(names = "-f", description = "fuzz run count", defaultValue = "0")
    int fuzz_count;
    @Option(names = "-n", description = "repeat count", defaultValue = "1")
    int repeat_count;
    @Option(names = "-t", description = "execution time", defaultValue = "PT0S")
    Duration execDuration;
    @Option(names = "-q", description = "quiet mode", defaultValue = "false")
    boolean quietMode;
    @Option(names = "-i", description = "init count", defaultValue = "1")
    int init_count;
    @Option(names = "-b", description = "set ttf-bug mode", defaultValue = "false")
    boolean ttfMode;

    @Parameters(index= "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = FuzzCandidates.class)
    String[] fileNames;

    public static Map<ChimeraTTF, Duration> foundTTFMap;
    public static String failedPath;
    public static String interestingPath;
    public static String logDir;
    public static PrintStream statOut;
    public static PrintStream ttfOut;
    public static LocalDateTime startFuzzDate;

    // Support auto-completion file arguments
    static class FuzzCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            File scenarioDir = new File(IFuzzer.scenarioPath);
            if (!scenarioDir.isDirectory())
                return Collections.emptyIterator();

            File[] scenarioFiles = scenarioDir.listFiles(File::isFile);
            if (scenarioFiles == null || scenarioFiles.length == 0)
                return Collections.emptyIterator();

            return (Arrays.stream(scenarioFiles)
                    .map(File::getName)
                    .collect(Collectors.toList())
                    .iterator());
        }
    }

    @Override
    public void run() {
        CommonUtil.saveRuntimeConfig();
        CommonUtil.setRuntimeConfigTTFMode(ttfMode);
        CommonUtil.setRuntimeConfigApplyDiffP4Rules(ConfigConstants.CONFIG_APPLY_DIFF_P4_RULES);

        if (ttfMode) {
            foundTTFMap = new HashMap<>();
            // add 1 sec on flow wait timeout
            CommonUtil.setRuntimeConfigFlowWaitTimeoutSec(ConfigConstants.CONFIG_FLOW_WAIT_TIMEOUT_SEC + 1);
        }

        List<File> scenarioFiles;
        try {
            scenarioFiles = CommonUtil.readAllFiles(fileNames, IFuzzer.scenarioPath);
        } catch (IOException e) {
            parent.out.println("Error: " + e.getMessage());
            return;
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

        if (!quietMode) {
            String curDate = LocalDateTime.now()
                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

            logDir = IFuzzer.scenarioPath + File.separator + curDate;
            failedPath = logDir + File.separator + "failure";
            interestingPath = logDir + File.separator + "interesting";
            File replayDir = new File(logDir);
            if (!replayDir.exists()) {
                if (!replayDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", logDir);
                    System.exit(2);
                }
            }

            try {
                File statFile = new File(logDir + File.separator + "stat.out");
                statOut = new PrintStream(statFile);
                statOut.println(scenarioGuidance.getStatsHeader());
                statOut.flush();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(2);
            }

            if (ttfMode) {
                try {
                    File ttfFile = new File(logDir + File.separator + "ttf.out");
                    ttfOut = new PrintStream(ttfFile);
                } catch (IOException e) {
                    e.printStackTrace();
                    System.exit(2);
                }
            }

            File failedDir = new File(failedPath);
            if (!failedDir.exists()) {
                if (!failedDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", failedPath);
                    System.exit(2);
                }
            }

            File interestingDir = new File(interestingPath);
            if (!interestingDir.exists()) {
                if (!interestingDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", interestingPath);
                    System.exit(2);
                }
            }

            // TODO: store current config
        }

        /* initialize guidance */
        try {
            parent.scenarioStore.init();
            if (scenarioGuidance instanceof SingleIntentGuidance) {
                scenarioGuidance.addSeeds(scenarioList);
            }
            scenarioGuidance.init(parent.configTopoGraph, logDir);
            globalTopoGuidance.init(parent.topoGraph);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }

        if (scenarioList.size() < init_count) {
            Queue<FuzzScenario> tmpList = new LinkedList<>(scenarioList);
            Iterator<FuzzScenario> it = scenarioList.iterator();
            for (int tmpSize = tmpList.size(); tmpSize < init_count; tmpSize++) {
                if (!it.hasNext()) {
                    it = scenarioList.iterator();
                }
                FuzzScenario scenario = it.next();
                FuzzScenario copiedScenario = FuzzScenario.copy(scenario);
                copiedScenario.dontFuzz();
                tmpList.add(copiedScenario);
            }

            scenarioList = tmpList;
        }

        FuzzResult totalResult = new FuzzResult();
        FuzzResult fuzzResult = new FuzzResult();
        LocalDateTime startDate = LocalDateTime.now();
        startFuzzDate = null;
        boolean updateDate = true;
        long execCnt = 0;
        boolean isFuzzing = false;

        /** Main Loop: Execute scenarios **/
        FuzzScenario scenario = null;
        while (!scenarioList.isEmpty()) {
            scenario = scenarioList.poll();

            // Start measure time
            if (scenario.getFuzzCnt() == 1 && updateDate) {
                startFuzzDate = LocalDateTime.now();
                parent.scenarioStore.setStartFuzzing(startFuzzDate, execDuration);
                scenarioGuidance.setStartFuzzing(startFuzzDate, execDuration);
                updateDate = false;
            }

            for (int i = 0; i < repeat_count; i++) {
                if (i > 0) {
                    scenario = FuzzScenario.copy(scenario);             // COPY
                }

                // EXECUTE IT !
                String errorMsg = parent.scenarioStore.execute(scenario);
                totalResult.addResult(scenario, errorMsg);
                if (scenario.isFuzzed()) {
                    fuzzResult.addResult(scenario, errorMsg);
                    // Once the scenario has fuzzed, check it as fuzzing.
                    isFuzzing = true;
                }
                execCnt ++;

                if (errorMsg == null) {
                    parent.out.printf("%s\n\n", scenario.getResult());
                    parent.out.flush();

                } else {
                    parent.out.println(errorMsg);
                    parent.out.println();
                    return;
                }

                // If scenario has TTF
                if (ttfMode) {
                    Set<ChimeraTTF> foundTTFSet = scenario.getFoundTTFSet();
                    foundTTFSet.addAll(P4Util.afterCheckTTFFromScenario(scenario));
                    if (!updateDate) {
                        for (ChimeraTTF foundTTF : foundTTFSet) {
                            if (foundTTF.equals(ChimeraTTF.NO_BUG) || foundTTFMap.containsKey(foundTTF))
                                continue;

                            Duration foundTTFTime = Duration.between(startFuzzDate, LocalDateTime.now());
                            foundTTFMap.put(foundTTF, foundTTFTime);
                            ttfOut.printf("%d %d.%d\n", foundTTF.getIdx(), foundTTFTime.getSeconds(),
                                    TimeUnit.NANOSECONDS.toMillis(foundTTFTime.getNano()));
                            ttfOut.flush();
                            scenario.logScenario(logDir + File.separator + "bug-" + foundTTF);
                        }
                    }
                }

                // While giving feedback, scenario could be truncated.
                parent.scenarioStore.feedbackResult(scenario);

                // Try to store it, always.
                storeScenario(scenario, execCnt, isFuzzing);
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

                    if (fuzz_count < 0 || scenario.getFuzzCnt() < fuzz_count || startFuzzDate == null ||
                            Duration.between(startFuzzDate, LocalDateTime.now()).compareTo(execDuration) < 0) {
                        scenarioList.add(scenarioGuidance.getRandomScenario());      // FUZZ

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

        String totalResultStr = "[TOTAL] " + totalResult.getSummary() + " (" +
                Duration.between(startDate, LocalDateTime.now()).toString() + ")";
        parent.out.println(totalResultStr);

        String fuzzResultStr = "";
        if (startFuzzDate != null) {
            fuzzResultStr = "[FUZZ] " + fuzzResult.getSummary() + " (" +
                    Duration.between(startFuzzDate, LocalDateTime.now()).toString() + ")";
            parent.out.println(fuzzResultStr);
        }

        if (!quietMode) {
            scenarioGuidance.storeMetadata(logDir);
            try {
                File resultFile = new File(logDir + File.separator + "result.out");
                PrintStream resultOut = new PrintStream(resultFile);
                resultOut.println(totalResultStr);
                if (!fuzzResultStr.isEmpty())
                    resultOut.println(fuzzResultStr);
                String resultStr = scenarioGuidance.getResultsString();
                if (resultStr != null && !resultStr.isEmpty())
                    resultOut.println(resultStr);

                if (statOut != null) {
                    statOut.println(scenarioGuidance.getStatsString());
                    statOut.flush();
                    statOut.close();
                }
                resultOut.close();
                if (ttfOut != null) {
                    ttfOut.flush();
                    ttfOut.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        CommonUtil.restoreRuntimeConfig();
    }

    boolean storeOnce = true;

    private void storeScenario(FuzzScenario scenario, long execCnt, boolean isFuzzing) {
        /*
         * TODO: store result.txt and current config (running arg, guidance, etc.)
         */
        boolean logScenario = false;

        // Log scenario
        if (scenario.isFuzzed()) {
            if (scenario.doesRequireLogging()) {
                logScenario = true;
            }

            if (scenario.getFuzzCnt() > 300 && storeOnce) {
                storeOnce = false;
                logScenario = true;
            }
            /*
             * Make log depending on the guidance
             * - NO/Syntax/AFL: log if scenario is verified
             * - Topology: log if scenario is NOT verified
             */
            if (scenarioGuidance.doesRequireLogging(scenario)) {
                logScenario = true;
            }
        }

        // log failed scenario
        if (logScenario) {
            String fileName = LocalDateTime.now()
                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
            scenario.logScenario(failedPath + File.separator + fileName);
        }

        if (!quietMode) {
            if (execCnt % ConfigConstants.CONFIG_MEASURE_STAT_INTERVAL == 1) {
                assert (statOut != null);
                statOut.println(scenarioGuidance.getStatsString() + (isFuzzing ? "" : " [SEED]"));
                statOut.flush();
            }
        }
    }
}
