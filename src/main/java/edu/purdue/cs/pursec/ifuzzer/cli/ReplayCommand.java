package edu.purdue.cs.pursec.ifuzzer.cli;


import com.google.common.collect.Lists;
import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.api.ScenarioData;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.DeviceCodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.JavaCodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.*;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.tools.ExecFileLoader;
import org.jline.reader.Completer;
import org.jline.reader.MaskingCallback;
import p4testgen.P4Testgen;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.HttpURLConnection;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.scenarioGuidance;

@Command(name = "replay", mixinStandardHelpOptions = true)
public class ReplayCommand implements Runnable {

    private final int byteBufferSize = 1 << 16;

    @ParentCommand
    CliCommands parent;

    // TODO: make ibn-fuzzer home dir environment (IBNF_HOME)
    private static final String failedPath = System.getProperty("user.dir") +
            File.separator + "scenarios";
    private static final String REPLAY_RESULT_FILENAME = "replay-result.out";
    private static String replayDirPath;
    private static String coverageDirPath;
    public static String [] COV_NAMES = {"onos", "bmv2", "p4_stmt", "p4_action"};
    public static PrintStream replayFailedOut;
    public static PrintStream replayResultOut;
    public static TopologyIntentGuidance localTopoGuidance;

    public ReplayCommand() {}

    @Parameters(index= "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = ReplayCandidates.class)
    String[] fileNames;
    @Option(names = "-n", description = "repeat count", defaultValue = "1")
    int repeat_count;
    @Option(names = "-i", description = "interactive mode")
    boolean isInteractive;
    @Option(names = "-t", description = "run all intents for given topology", defaultValue = "false")
    boolean topoAwareMode;
    @Option(names = "-e", description = "exec hard count", defaultValue = "0")
    int hard_exec_count;
    @Option(names = "-d", description = "delete false-positive errors", defaultValue = "false")
    boolean delFPMode;
    @Option(names = "-m", description = "multiply wait timeout values", defaultValue = "1")
    int mulWaitTime;
    @Option(names = "-s", description = "skip errorActionCmd to replay", defaultValue = "")
    String skipErrorActionCmd;
    @Option(names = "-c", description = "select errorActionCmd to replay", defaultValue = "")
    String replayErrorActionCmd;
    @Option(names = "-p", description = "previous replay directory", defaultValue = "")
    String prevReplayDirPath;
    @Option(names = "-k", description = "select packetType to replay", defaultValue = "-1")
    int replayPacketType;

    // Support auto-completion file arguments
    static class ReplayCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            File scenarioDir = new File(failedPath);
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

    private void initializeBeforeReplay() {
        // Create replayDirectory
        String curDate = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

        replayDirPath = failedPath + File.separator + curDate + "-Replay";
        File replayDir = new File(replayDirPath);
        if (!replayDir.exists()) {
            if (!replayDir.mkdir()) {
                System.err.printf("Cannot create %s\n", replayDirPath);
                System.exit(2);
            }
        }

        coverageDirPath = replayDirPath + File.separator + "coverage";
        File coverageDir = new File(coverageDirPath);
        if (!coverageDir.exists()) {
            if (!coverageDir.mkdir()) {
                System.err.printf("Cannot create %s\n", coverageDirPath);
                System.exit(2);
            }
        }

        for (String covName : COV_NAMES) {
            coverageDir = new File(coverageDirPath + File.separator + covName);
            if (!coverageDir.exists()) {
                if (!coverageDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", coverageDirPath + File.separator + covName);
                    System.exit(2);
                }
            }
        }

        if (!prevReplayDirPath.isEmpty()) {
            Path prevResultPath = Paths.get(failedPath + File.separator + prevReplayDirPath +
                    File.separator + REPLAY_RESULT_FILENAME);
            Path newResultPath = Paths.get(replayDirPath + File.separator + REPLAY_RESULT_FILENAME);
            try {
                Files.copy(prevResultPath, newResultPath, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                System.err.printf("Cannot copy %s: %s\n", prevResultPath, e.getMessage());
                System.exit(2);
            }
        }

        // log failed scenario
        try {
            File replayFailedFile = new File(replayDirPath + File.separator + "failed.out");
            replayFailedOut = new PrintStream(replayFailedFile);
            File replayResultFile = new File(replayDirPath + File.separator + REPLAY_RESULT_FILENAME);
            replayResultOut = new PrintStream(new FileOutputStream(replayResultFile, true));
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

    private boolean deleteFalsePositiveFiles(List<File> falsePositiveFiles) {
        /* Clear falsePositives */
        if (falsePositiveFiles.isEmpty())
            return false;

        /* disable completer */
        Completer completer = parent.reader.getCompleter();
        parent.reader.setCompleter(null);

        boolean doubleChecked = false;
        while (true) {
            String prompt;
            if (doubleChecked) {
                prompt = "Confirm? (y/N)> ";
            } else {
                prompt = String.format("Remove %d FP file(s)? (y/N)> ", falsePositiveFiles.size());
            }

            String input = parent.reader.readLine(prompt, null, (MaskingCallback) null, null)
                    .trim().toLowerCase();
            if (input.length() == 0 || input.equals("n")) {
                break;

            } else if (input.equals("y")) {
                if (!doubleChecked) {
                    doubleChecked = true;
                    continue;
                }

                // Delete
                for (File delFile : falsePositiveFiles) {
                    if (delFile.delete()) {
                        System.out.println("Delete the file: " + delFile.getName());
                    } else {
                        System.out.println("Failed to delete the file.");
                    }
                }
                break;
            }
        }
        /* refresh */
        parent.reader.setCompleter(completer);
        return true;
    }

    @Override
    public void run() {
        if (!skipErrorActionCmd.isEmpty() && !replayErrorActionCmd.isEmpty()) {
            parent.out.printf("Error: select one option -s or -c\n");
            return;
        }

        // Replay mode needs to check TTF
        CommonUtil.setRuntimeConfigTTFMode(true);
        Queue<ScenarioData> scenarioQueue;

        if (fileNames[0].equals("ALL")) {
            // Get all scenarios
            File scenarioDir = new File(failedPath);
            if (!scenarioDir.isDirectory()) {
                parent.out.printf("Error: cannot find path %s\n", failedPath);
                return;
            }
            try {
                scenarioQueue = Files.walk(Paths.get(failedPath))
                        .filter(Files::isRegularFile)
                        .map(Path::toFile)
                        .filter(k -> !k.getPath().endsWith(".swp"))
                        .sorted()
                        .map(ScenarioData::new)
                        .collect(Collectors.toCollection(LinkedList::new));
            } catch (IOException ioe) {
                parent.out.printf("Error: %s\n", ioe);
                return;
            }
        } else {
            // Get file
            List<File> files = Arrays.stream(fileNames)
                    .map(s -> failedPath + File.separator + s)
                    .filter(k -> !k.contains(".."))
                    .map(File::new)
                    .collect(Collectors.toList());

            scenarioQueue = new LinkedList<>();
            for (File file : files) {
                if (file.isFile()) {
                    // add regular files
                    scenarioQueue.add(new ScenarioData(file));
                } else if (file.isDirectory()) {
                    // add regular files in directory
                    try {
                        scenarioQueue.addAll(Files.walk(Paths.get(file.getPath()))
                                .filter(Files::isRegularFile)
                                .map(Path::toFile)
                                .filter(k -> !k.getPath().endsWith(".swp"))
                                .sorted()
                                .map(ScenarioData::new)
                                .collect(Collectors.toCollection(LinkedList::new)));
                    } catch (IOException ioe) {
                        parent.out.printf("Error: %s\n", ioe);
                        return;
                    }
                }
            }
        }

        List<File> falsePositiveFiles = new LinkedList<>();

        if (!prevReplayDirPath.isEmpty()) {
            // Assume that file names in replay-result.out are sorted
            try {
                String prevReplayResultFilePath = failedPath + File.separator + prevReplayDirPath +
                        File.separator + REPLAY_RESULT_FILENAME;
                BufferedReader reader = new BufferedReader(new FileReader(prevReplayResultFilePath));

                while (true) {
                    String line = reader.readLine();
                    // 1) Stop if no more previous line
                    if (line == null)
                        break;
                    String[] words = line.split(" ");
                    if (words.length < 1)
                        break;

                    ScenarioData scenarioData = scenarioQueue.peek();
                    // 2) Stop if no more data in queue
                    if (scenarioData == null)
                        break;

                    if (!words[0].equals(scenarioData.getFileName()))
                        break;

                    if (words[words.length - 1].equals("(FP)")) {
                        // Check whether prev scenario was FP
                        falsePositiveFiles.add(scenarioData.getFile());
                    }

                    scenarioQueue.poll();
                }
            } catch (RuntimeException | IOException e) {
                parent.out.printf("Cannot read %s: %s\n", prevReplayDirPath, e);
                return;
            }
        }

        if (scenarioQueue.isEmpty()) {
            parent.out.printf("No file to replay\n");
            deleteFalsePositiveFiles(falsePositiveFiles);
            return;
        }

        parent.out.printf("REPLAY %s%d scenarios\n",
                hard_exec_count > 0 ? hard_exec_count + " / " : "",
                scenarioQueue.size());
        parent.out.flush();

        // Disable isInteractive when repeat count > 1
        if (repeat_count > 1 || hard_exec_count > 1)
            isInteractive = false;

        if (topoAwareMode) {
            try {
                localTopoGuidance = new TopologyIntentGuidance();
                localTopoGuidance.init(parent.topoGraph);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(2);
            }
        }

        CommonUtil.saveRuntimeConfig();
        CommonUtil.multiplyWaitTimes(mulWaitTime);
        CommonUtil.setRuntimeConfigApplyDiffP4Rules(false);

        initializeBeforeReplay();

        try {
            parent.scenarioStore.init();
            scenarioGuidance.init(parent.configTopoGraph, replayDirPath);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }

        // Main Loop: Execute scenarios
        Map<List<Byte>, Integer> traceMaps = new HashMap<>();
        FuzzScenario scenario = null;
        JavaCodeCoverage aggregateCov = new JavaCodeCoverage();
        Map<String, DeviceCodeCoverage> deviceCodeCoverageMap = new HashMap<>();
        if (hard_exec_count <= 0) {
            if (repeat_count > 1)
                hard_exec_count = Integer.MAX_VALUE;        // Set as max
            else
                hard_exec_count = scenarioQueue.size();      // Set as size
        }
        int local_exec_cnt = 0, mismatch_cnt = 0;
        boolean genLoadHost = true;
        while (!scenarioQueue.isEmpty() && local_exec_cnt < hard_exec_count) {
            ScenarioData scenarioData = scenarioQueue.poll();
            if (!skipErrorActionCmd.isEmpty() || !replayErrorActionCmd.isEmpty()) {
                try {
                    JsonObject scenarioJson = scenarioData.getFuzzScenarioJson();
                    String errorActionCmd = "";
                    if (scenarioJson.has("errorActionCmd")) {
                        errorActionCmd = scenarioJson.get("errorActionCmd").getAsString();
                    }

                    // Skip when error action command matches
                    if (!skipErrorActionCmd.isEmpty() &&
                            skipErrorActionCmd.equals(errorActionCmd))
                        continue;

                    // Replay only error action command matches
                    if (!replayErrorActionCmd.isEmpty() &&
                            !replayErrorActionCmd.equals(errorActionCmd))
                        continue;

                } catch (IOException e) {
                    parent.out.printf("Error in reading scenario: %s\n", e.getMessage());
                    parent.out.flush();
                    continue;
                }
            }

            try {
                scenario = scenarioData.getFuzzScenario(genLoadHost);

                // Replay scenarios only with a specific packet type
                if (replayPacketType >= 0) {
                    P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(scenario);
                    if (testCase == null)
                        continue;

                    int curPacketType = P4Util.genPacketType(testCase);
                    if (curPacketType != replayPacketType)
                        continue;
                }

                scenarioGuidance.preprocess(scenario);
                // generate "load-hosts" once.
                if (genLoadHost)
                    genLoadHost = false;

            } catch (IOException e) {
                parent.out.printf("Error in reading scenario: %s\n", e.getMessage());
                parent.out.flush();
                continue;
            }

            for (int i = 0; i < repeat_count; i++) {
                if (i > 0)
                    scenario = FuzzScenario.copy(scenario);

                // Clear coverage
                if (!ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE) {
                    try {
                        HttpURLConnection conn = TestUtil.requestClearCov();
                        if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300) {
                            parent.out.println("Error in requesting clear coverage of devices");
                            parent.out.flush();
                        }
                    } catch (IOException e) {
                        parent.out.printf("Error in requesting clear coverage of devices: %s\n", e.getMessage());
                        parent.out.flush();
                    }
                }

                boolean isMismatched = false;
                if (isInteractive) {
                    /* disable completer */
                    Completer completer = parent.reader.getCompleter();
                    parent.reader.setCompleter(null);

                    // TODO: do not save y/n in history
                    parent.scenarioStore.execute(scenario, parent.reader);

                    /* refresh */
                    parent.reader.setCompleter(completer);

                } else {
                    parent.scenarioStore.execute(scenario);

                    // compare errorMsgs
                    if (scenario.cmpResult() != 0) {
                        isMismatched = true;
                        mismatch_cnt++;
                    } else if (delFPMode && scenario.getErrorMsg() != null) {
                        // If fuzzer succeeds in replaying error file, delete the file
                        isMismatched = true;
                        mismatch_cnt++;
                    }
                }

                EnumSet<ChimeraTTF> foundTTFSet = scenario.getFoundTTFSet();
                foundTTFSet.addAll(P4Util.afterCheckTTFFromScenario(scenario));
                StringBuilder foundTTFStr = new StringBuilder();
                for (ChimeraTTF foundTTF : foundTTFSet) {
                    if (foundTTF.equals(ChimeraTTF.NO_BUG))
                        continue;

                    parent.out.printf("** BUG-%d has been found **\n", foundTTF.getIdx());
                    if (foundTTFStr.length() == 0)
                        foundTTFStr.append("BUG-");
                    else
                        foundTTFStr.append(",");
                    foundTTFStr.append(foundTTF.getIdx());
                    parent.out.flush();
                }

                local_exec_cnt ++;
                if (repeat_count > 1) {
                    parent.out.printf("[%d/%d] %s\n\n", i + 1, repeat_count, scenario.getResult());
                    parent.out.flush();
                } else {
                    parent.out.printf("[%d/%d/%d] %s\n", mismatch_cnt, local_exec_cnt,
                            hard_exec_count, scenario.getResult());
                    if (scenario.getReplayFile() != null) {
                        StringBuilder replayResultSb = new StringBuilder();
                        if (isMismatched) {
                            parent.out.printf("%s - mismatched: %s\n", scenario.getReplayFile().getName(),
                                    scenario.prevResult());
                            replayResultSb.append(scenario.getReplayFile().getName()).append(" ");
                            replayResultSb.append(scenario.prevResult()).append(" ");
                            if (scenario.getErrorMsg() == null || delFPMode) {
                                falsePositiveFiles.add(scenario.getReplayFile());
                                replayResultSb.append("(FP)");
                            } else {
                                replayResultSb.append("(FN)");
                            }
                        }

                        if (scenario.getErrorMsg() != null) {
                            if (!isMismatched) {
                                replayResultSb.append(scenario.getReplayFile().getName()).append(" ");
                                replayResultSb.append(scenario.prevResult());
                            }
                            if (foundTTFSet.isEmpty()) {
                                replayResultSb.append(" (unknown bug)");
                            } else {
                                replayResultSb.append(" ").append(foundTTFStr);
                            }
                        }
                        replayResultOut.println(replayResultSb);
                        replayResultOut.flush();
                    }

                    if (scenario.getErrorMsg() != null) {
                        replayFailedOut.println(scenario.getReplayFile().getName());
                        replayFailedOut.flush();
                    }
                    parent.out.println();
                    parent.out.flush();
                }

                if (!isInteractive) {
                    ExecFileLoader loader = scenario.getCodeCoverage().getLoader();
                    Byte[] traceBits = FuzzUtil.getCoverageBitmaps(loader, byteBufferSize);
                    List<Byte> traceBitList = Lists.newArrayList(traceBits);
                    traceMaps.compute(traceBitList, (k, v) -> (v == null) ? 1 : v + 1);
                }

                if (ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE) {
                    aggregateCov.updateCoverage(scenario.getCodeCoverage());

                } else {
                    aggregateCov.diffCoverage(scenario.getCodeCoverage());
                    List<DeviceCodeCoverage> deviceCodeCoverages = scenario.getDeviceCodeCoverages();
                    if (deviceCodeCoverages != null) {
                        for (DeviceCodeCoverage deviceCodeCoverage : deviceCodeCoverages) {
                            String deviceId = deviceCodeCoverage.getDeviceId();
                            if (deviceCodeCoverageMap.containsKey(deviceId)) {
                                deviceCodeCoverageMap.get(deviceId).diffCoverage(deviceCodeCoverage);
                            } else {
                                deviceCodeCoverageMap.put(deviceId, new DeviceCodeCoverage(deviceCodeCoverage));
                            }
                        }
                    }
                }
                // Store coverage data
                FuzzScenario finalScenario = scenario;
                finalScenario.getCodeCoverage().storeCoverageMap(coverageDirPath + File.separator +
                        COV_NAMES[0] + File.separator + finalScenario.getName() + ".ttf");

                if (finalScenario.getP4ActionCoverages() != null)
                    finalScenario.getDeviceCodeCoverages()
                            .forEach(k -> k.storeCoverageMap(coverageDirPath + File.separator +
                                    COV_NAMES[1] + File.separator +
                                    finalScenario.getName() + k.getDeviceId() + ".ttf"));
                if (finalScenario.getP4StatementCoverages() != null)
                    finalScenario.getP4StatementCoverages()
                            .forEach(k -> k.storeCoverageMap(coverageDirPath + File.separator +
                                    COV_NAMES[2] + File.separator +
                                    finalScenario.getName() + k.getDeviceId() + ".ttf"));
                if (finalScenario.getP4ActionCoverages() != null)
                    finalScenario.getP4ActionCoverages()
                            .forEach(k -> k.storeCoverageMap(coverageDirPath + File.separator +
                                    COV_NAMES[3] + File.separator +
                                    finalScenario.getName() + k.getDeviceId() + ".ttf"));

                scenarioGuidance.feedbackResult(scenario);
            }

            if (topoAwareMode) {
                try {
                    // Fuzz it
                    FuzzScenario fuzzScenario = FuzzScenario.fuzz(scenario);
                    if (fuzzScenario != null)
                        scenarioQueue.add(new ScenarioData(fuzzScenario));
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (EndFuzzException | SkipFuzzException e) {
                    /** stop fuzz **/
                    if (scenario != null && ConfigConstants.CONFIG_ENABLE_COVERAGE_LOGGING) {
                        storeScenario(scenario, true);
                    }
                    scenarioQueue.clear();
                }
            } else if (!isInteractive && !ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE) {
                storeScenario(scenario, aggregateCov, deviceCodeCoverageMap);
            }
        }

        if (topoAwareMode) {
            localTopoGuidance.stop();
        }
        scenarioGuidance.stop();

        if (replayFailedOut != null)
            replayFailedOut.close();

        if (replayResultOut != null)
            replayResultOut.close();

        if (ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE && scenario != null) {
            storeScenario(scenario, aggregateCov, deviceCodeCoverageMap);
        }

        if (scenario != null)
            parent.scenarioStore.revertAllConfigTopoOperations(scenario);

        parent.out.printf("[REPLAY RESULT] %d/%d paths\n", traceMaps.keySet().size(), repeat_count);
        deleteFalsePositiveFiles(falsePositiveFiles);

        CommonUtil.restoreRuntimeConfig();
    }

    private void storeScenario(@Nonnull FuzzScenario scenario, boolean storeGlobalCoverage) {

        JavaCodeCoverage codeCoverage = scenario.getCodeCoverage();
        if (storeGlobalCoverage && localTopoGuidance != null) {
            if (localTopoGuidance.getCodeCoverage() != null)
                codeCoverage = localTopoGuidance.getCodeCoverage();
        }

        storeScenario(scenario, codeCoverage, null);
    }

    private void storeScenario(@Nonnull FuzzScenario scenario, JavaCodeCoverage codeCoverage,
                               Map<String, DeviceCodeCoverage> deviceCodeCoverageMap) {
        ExecFileLoader loader = codeCoverage.getLoader();

        try {
            // 1) write JSON
            FileWriter fileWriter = new FileWriter(replayDirPath + File.separator + "input.json");
            Gson gson = new Gson();
            gson.toJson(scenario.toJsonObject(), fileWriter);
            fileWriter.flush();
            fileWriter.close();

            // 2) write jacoco.exec
            loader.save(new File(replayDirPath + File.separator + "coverage.exec"), false);

            // 3) write bitmap (hash id)
            ByteBuffer feedback = ByteBuffer.allocate(byteBufferSize);
            feedback.order(ByteOrder.LITTLE_ENDIAN);
            Byte[] traceBits = FuzzUtil.getCoverageBitmaps(loader, byteBufferSize);

            for (int i = 0; i < byteBufferSize; i++) {
                feedback.put(traceBits[i]);
            }

            OutputStream fw = new BufferedOutputStream(new FileOutputStream(replayDirPath + File.separator + "bitmap.out"));
            fw.write(feedback.array(), 0, feedback.position());
            fw.flush();
            fw.close();

            // 4) write bitmap (string id)
            BufferedReader classFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSClassListFilePath()));
            Map<String, Integer> classMap = new HashMap<>();

            PrintStream pw = new PrintStream(replayDirPath + File.separator + "coverage.out");

            String clLine;
            while ((clLine = classFileReader.readLine()) != null) {
                classMap.put(clLine, 0);
            }

            int hitCnt = 0, totalCnt = 0;
            for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
                int cnt = 0;
                for (boolean probe : data.getProbes()) {
                    if (probe) {
                        cnt++;
                        hitCnt++;
                    }
                }
                totalCnt += data.getProbes().length;
                int ret = classMap.getOrDefault(data.getName(), -1);

                pw.println(String.format("[%s] %s: %d", ret < 0 ? "X" : "O", data.getName(), cnt));
            }
            pw.close();

            // 5) stat.out
            File statFile = new File(replayDirPath + File.separator + "stat.out");
            PrintStream statOut = new PrintStream(statFile);
            statOut.println(JavaCodeCoverage.getStatsHeader() + ", " +
                    DeviceCodeCoverage.getStatsHeader());
            statOut.printf("%d, %d, ", hitCnt, totalCnt);
            statOut.print(codeCoverage.getStatsString());
            if (deviceCodeCoverageMap != null) {
                for (DeviceCodeCoverage devCov : deviceCodeCoverageMap.values()) {
                    statOut.print(", " + devCov.getStatsString(false));
                }
            }
            statOut.println();
            statOut.flush();
            statOut.close();

            statFile = new File(replayDirPath + File.separator + "guidance-stat.out");
            statOut = new PrintStream(statFile);
            statOut.println(scenarioGuidance.getStatsHeader());
            statOut.println(scenarioGuidance.getStatsString());
            statOut.flush();
            statOut.close();


            statFile = new File(replayDirPath + File.separator + "allBranch.out");
            statOut = new PrintStream(statFile);
            scenario.getCodeCoverage().analyze(statOut);
            statOut.flush();
            statOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
