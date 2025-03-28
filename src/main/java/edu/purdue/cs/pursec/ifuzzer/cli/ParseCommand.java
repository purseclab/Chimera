package edu.purdue.cs.pursec.ifuzzer.cli;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import p4testgen.P4Testgen;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Command(name = "parse", mixinStandardHelpOptions = true)
public class ParseCommand implements Runnable {
    @ParentCommand
    CliCommands parent;

    @Parameters(index = "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = ParseCandidates.class)
    String[] fileNames;

    @Option(names = "-s", description = "store given file(s)", defaultValue = "false")
    boolean doesStore;

    @Option(names = "-p", description = "specify to print status", defaultValue = "false")
    boolean printStatus;

    static final String storePath = System.getProperty("user.dir") +
            File.separator + "scenarios" + File.separator + "parse";

    // Support auto-completion file arguments
    static class ParseCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            File scenarioDir = new File(IFuzzer.rootPath + File.separator + "scenarios");
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
        List<File> scenarioFiles;
        try {
            scenarioFiles = CommonUtil.readAllFiles(fileNames, IFuzzer.scenarioPath);
        } catch (IOException e) {
            parent.out.println("Error: " + e.getMessage());
            return;
        }

        scenarioFiles = scenarioFiles.stream()
                .sorted(Comparator.comparing(File::getName))
                .collect(Collectors.toList());

        Map<Integer, Integer> allPacketTypeMap = new HashMap<>();
        Map<Integer, Integer> uniqPacketTypeMap = new HashMap<>();
        Queue<String> scenarioQueue = new LinkedList<>();
        List<String> uniqFileList = new ArrayList<>();

        /* parse scenarios from given files */
        for (File scenarioFile : scenarioFiles) {
            try {
                JsonObject scenarioJson = TestUtil.fromJson(new FileReader(scenarioFile));

                if (scenarioJson != null) {
                    FuzzScenario scenario = new FuzzScenario(scenarioJson);

                    String errorActionCmd = "";
                    if (scenarioJson.has("errorActionCmd")) {
                        errorActionCmd = scenarioJson.get("errorActionCmd").getAsString();
                    }

                    if (!printStatus) {
                        parent.out.println("Parsed scenario");
                        for (FuzzAction action : scenario.getActionList()) {
                            parent.out.printf("[%s] %s\n", action.getId(), action.getActionCmd());
                        }
                    }

                    P4Testgen.TestCase testCase = P4Util.getP4TestgenFromScenario(scenario);
                    if (testCase != null && errorActionCmd.equals("dp-verify-rule")) {
                        int packetType = P4Util.genPacketType(testCase);
                        allPacketTypeMap.put(packetType, allPacketTypeMap.getOrDefault(packetType, 0) + 1);

                        String scenarioId = P4Util.getP4TestgenIdFromScenario(scenario);

                        boolean isUnique = true;
                        for (String scenario1 : scenarioQueue) {
                            if (scenario1.equals(scenarioId)) {
                                isUnique = false;
                                break;
                            }
                        }

                        if (isUnique) {
                            uniqPacketTypeMap.put(packetType, uniqPacketTypeMap.getOrDefault(packetType, 0) + 1);
                            scenarioQueue.add(scenarioId);
                            String fpCases = "";
                            if (P4Util.check_P4CE_FP_overwrite_action(testCase)) {
                                fpCases += " P4CE1";
                            }
                            if (P4Util.check_P4CE_FP_multiple_output(testCase)) {
                                fpCases += " P4CE2";
                            }
                            uniqFileList.add(scenarioFile.getName() + " " +
                                    P4Util.getPacketTypeStr(packetType) + fpCases);
                        }

                        if (scenarioQueue.size() > ConfigConstants.CONFIG_P4_FUZZ_PACKET_CNT * 2)
                            scenarioQueue.poll();

                    } else {
                        uniqFileList.add(scenarioFile.getName());
                    }

                    if (doesStore) {
                        String storeFileName = LocalDateTime.now()
                                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

                        File storeDir = new File(storePath);
                        if (!storeDir.exists()) {
                            if (!storeDir.mkdir()) {
                                System.err.printf("Cannot create %s\n", storePath);
                                System.exit(2);
                            }
                        }
                        String storeFilePath = storePath + File.separator + storeFileName;
                        scenario.logScenario(storeFilePath);
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
                parent.out.printf("Error while reading %s: %s\n", scenarioFile, e.getMessage());
            }
        }

        if (printStatus) {
            parent.out.printf("ALL:\n");
            for (Integer packetType : allPacketTypeMap.keySet()) {
                parent.out.printf("[%s] %d\n", P4Util.getPacketTypeStr(packetType), allPacketTypeMap.get(packetType));
            }

            parent.out.printf("\nUNIQUE:\n");
            for (Integer packetType : uniqPacketTypeMap.keySet()) {
                parent.out.printf("[%s] %d\n", P4Util.getPacketTypeStr(packetType), uniqPacketTypeMap.get(packetType));
            }

            try (FileWriter fw = new FileWriter(System.getProperty("user.dir") +
                        File.separator + "unique_scenario.out")) {
                fw.flush();
                PrintWriter pw = new PrintWriter(fw);
                for (String uniqFile : uniqFileList)
                    pw.println(uniqFile);
                pw.close();
            } catch (IOException e) {
                e.printStackTrace();
                parent.out.printf("Error while writing unique_scenario.out: %s\n", e.getMessage());
            }
        }
    }
}
