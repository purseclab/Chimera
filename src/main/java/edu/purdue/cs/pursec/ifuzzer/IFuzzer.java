package edu.purdue.cs.pursec.ifuzzer;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.CliCommands;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.impl.ONOSAgentInterface;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.JavaNames;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.RuleStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.jline.console.SystemRegistry;
import org.jline.console.impl.Builtins;
import org.jline.console.impl.SystemRegistryImpl;
import org.jline.keymap.KeyMap;
import org.jline.reader.*;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.widget.TailTipWidgets;
import picocli.CommandLine;
import picocli.shell.jline3.PicocliCommands;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class IFuzzer {
    private static final String ONOS_BIN_PATH_ENV = "ONOS_BIN_PATH";
    public static Path workDir() {
        return Paths.get(System.getProperty("user.dir"));
    }
    public static String rootPath;
    public static String intentPath;
    public static String scenarioPath;
    public static String ruleRelativePath;
    public static boolean[] methodBitmap;
    public static Set<String> methodSet;
    public static Set<File> classfiles;
    public static Map<String, String> classpathMap;
    public static Map<String, Integer> classSemanticMap;
    public static boolean hasSemantic;

    private static final TopoGraph graph = TopoGraph.getOperationalTopology();
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    private static final RuleStore ruleStore = RuleStore.getInstance();
    private static final IntentStore intentStore = IntentStore.getInstance();
    private static final ScenarioStore scenarioStore = ScenarioStore.getInstance();
    private static final FlowRuleStore flowRuleStore = FlowRuleStore.getInstance();
    private static final IntentInterface intentInterface = new ONOSAgentInterface();
//    private static final IntentInterface intentInterface = new ONOSRestInterface();

    private static final TopologyListenerService topoListener =
            new TopologyListenerService(graph);
    private static final IntentFuzzerService intentFuzzer =
            new IntentFuzzerService(graph, ruleStore, intentStore, scenarioStore, intentInterface);
    private static final IntentDecisionService intentDecision =
            new IntentDecisionService(graph, ruleStore, intentStore, scenarioStore, intentInterface);
    private static final NetworkTestManager networkTestManager =
            new NetworkTestManager(graph, configTopoGraph, ruleStore, intentStore, scenarioStore,
                    flowRuleStore, intentInterface);

    public static void main(String[] args) {

        // set up JLine built-in commands
        Builtins builtins = new Builtins(IFuzzer::workDir, null, null);
        builtins.rename(Builtins.Command.TTOP, "top");
        builtins.alias("zle", "widget");
        builtins.alias("bindkey", "keymap");

        // TODO: add services
        CliCommands commands = new CliCommands(graph, configTopoGraph, intentFuzzer,
                scenarioStore, flowRuleStore);
        CommandLine cmd = new CommandLine(commands);
        PicocliCommands picocliCommands = new PicocliCommands(cmd);

        // Preprocessing
        doPreprocess();

        // Start to receive rabbitMQ message
        topoListener.start();

        // Read intents from SDN controller
        intentFuzzer.start();

        // Listen REST from test-agent
        networkTestManager.start();

        try {

            Parser parser = new DefaultParser();
            try (Terminal terminal = TerminalBuilder.builder().build()) {
                SystemRegistry systemRegistry = new SystemRegistryImpl(parser, terminal, IFuzzer::workDir, null);
                systemRegistry.setCommandRegistries(builtins, picocliCommands);

                LineReader reader = LineReaderBuilder.builder()
                        .terminal(terminal)
                        .completer(systemRegistry.completer())
                        .parser(parser)
                        .variable(LineReader.LIST_MAX, 50)   // max tab completion candidates
                        .build();
                builtins.setLineReader(reader);
                commands.setReader(reader);
                TailTipWidgets widgets = new TailTipWidgets(reader, systemRegistry::commandDescription, 5, TailTipWidgets.TipType.COMPLETER);
                widgets.enable();
                KeyMap<Binding> keyMap = reader.getKeyMaps().get("main");
                keyMap.bind(new Reference("tailtip-toggle"), KeyMap.alt("s"));

                String prompt = "p4fuzzer> ";
                String rightPrompt = null;

                // start the shell and process input until the user quits with Ctrl-D
                String line;
                while (true) {
                    try {
                        systemRegistry.cleanUp();
                        line = reader.readLine(prompt, rightPrompt, (MaskingCallback) null, null);
                        systemRegistry.execute(line);
                    } catch (UserInterruptException e) {
                        // Ignore
                    } catch (EndOfFileException e) {
                        System.exit(0);
                    } catch (Exception e) {
                        systemRegistry.trace(e);
                    }
                }
            }

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    private static void doPreprocess() {
        String onosBinPath = "";
        try {
            rootPath = ".";
            if (System.getenv().containsKey("IFUZZER_ROOT"))
                rootPath = System.getenv("IFUZZER_ROOT");

            if (System.getenv().containsKey(ONOS_BIN_PATH_ENV))
                onosBinPath = System.getenv(ONOS_BIN_PATH_ENV);

            scenarioPath = System.getProperty("user.dir") +
                    File.separator + "scenarios";
            intentPath = scenarioPath + File.separator + ".intent";
            ruleRelativePath = "scenarios" + File.separator + ".intent";
            // Create directory.
            // 1. Clean inputDir
            File intentDir = new File(intentPath);
            if (!intentDir.exists()) {
                if (!intentDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", intentPath);
                    System.exit(2);
                }
            }

        } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(2);
        }

        // If no ONOS_BIN_PATH env, skip reading packages, classes, and methods.
        if (onosBinPath.isEmpty()) {
            System.out.printf("[WARN] %s is not configured.\n", ONOS_BIN_PATH_ENV);
            return;
        }

        /* Class List */
        try {
            BufferedReader classFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSClassListFilePath()));
            classpathMap = new HashMap<>();
            String clLine;
            while ((clLine = classFileReader.readLine()) != null) {
                classpathMap.put(clLine, "");
            }

        } catch (FileNotFoundException e) {
            System.out.printf("[WARN] %s is not found.\n", ONOSUtil.getONOSClassListFilePath());
        } catch (IOException e) {
            System.exit(2);
            e.printStackTrace(System.err);
        }

        /* Classpath List */
        try {
            BufferedReader classFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSClasspathListFilePath()));
            classfiles = new HashSet<>();
            String fileLine;
            int debugPrint = 10;
            String p4ClassPath = P4Util.getPipelineClassPath();
            if (p4ClassPath != null) {
                File clpathFile = new File(p4ClassPath);
                if (!clpathFile.exists()) {
                    System.out.printf("[WARN] %s is not found.\n", p4ClassPath);
                }

                for (String clazz : getAllClasses(clpathFile, "")) {
                    if (classpathMap.get(clazz) != null) {
                        classpathMap.put(clazz, p4ClassPath + "/" + clazz + ".class");
                        //System.out.printf("%s is at %s\n", clazz, p4ClassPath);
                    }
                }
                classfiles.add(clpathFile);
            }
            while ((fileLine = classFileReader.readLine()) != null) {
                if (fileLine.startsWith("#") || fileLine.length() == 0)
                    continue;

                if (P4Util.filterClassPath(fileLine))
                    continue;

                String clpathLine = onosBinPath + fileLine;
                File clpathFile = new File(clpathLine);
                if (!clpathFile.exists()) {
                    System.out.printf("[WARN] %s is not found.\n", clpathLine);
                }

                for (String clazz : getAllClasses(clpathFile, "")) {
                    if (P4Util.filterClass(clazz))
                        continue;

                    if (classpathMap.get(clazz) != null) {
                        classpathMap.put(clazz, clpathLine + "/" + clazz + ".class");

                        if (debugPrint > 0) {
                            System.out.printf("%s is at %s\n", clazz, clpathLine);
                            debugPrint --;
                        }
                    }
                }
                classfiles.add(clpathFile);
            }

            System.out.printf("...\n\n%d classes are found.\n", classpathMap.values().stream()
                    .filter(k -> !k.isEmpty())
                    .count());

            FileWriter fileWriter = new FileWriter(ONOSUtil.getONOSClassListOutputFilePath());
            classpathMap.entrySet().stream()
                    .filter(k -> !k.getValue().isEmpty())
                    .forEach(k -> {
                        try {
                            fileWriter.write(k.getKey() + " " + k.getValue() + "\n");
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
            fileWriter.close();

        } catch (FileNotFoundException e) {
            System.out.printf("[WARN] %s is not found.\n", ONOSUtil.getONOSClasspathListFilePath());
        } catch (IOException e) {
            System.exit(2);
            e.printStackTrace(System.err);
        }

        /* Method List */
        try {
            BufferedReader methodFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSMethodListFilePath()));
            methodBitmap = new boolean[ConfigConstants.COVERAGE_MAP_SIZE];
            methodSet = new HashSet<>();
            for (int i = 0; i < ConfigConstants.COVERAGE_MAP_SIZE; i++)
                methodBitmap[i] = false;

            String tmpLine;
            while ((tmpLine = methodFileReader.readLine()) != null) {
                String key = JavaNames.getKeyFromMethod(tmpLine, classpathMap.keySet());
                if (key == null)
                    continue;
                methodBitmap[JavaNames.getHash(key, ConfigConstants.COVERAGE_MAP_SIZE)] = true;
                methodSet.add(key);
//                methodMap.computeIfAbsent(hash(key), k -> new ArrayList<>()).add(key);

//                String[] mLines = tmpLine.split(" ");
//                methodMap2.put(mLines[0] + " " + mLines[2], 0);

            }

        } catch (FileNotFoundException e) {
            System.out.printf("[WARN] %s is not found.\n", ONOSUtil.getONOSMethodListFilePath());
        } catch (IOException e) {
            System.exit(2);
            e.printStackTrace(System.err);
        }

        try {
            BufferedReader classFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSClassContextListFilePath()));
            classSemanticMap = new HashMap<>();
            String clLine;
            while ((clLine = classFileReader.readLine()) != null) {
                if (clLine.startsWith("#") || clLine.length() == 0)
                    continue;
                String [] args = clLine.split(" ");
                try {
                    int lvl = Integer.parseInt(args[0]);
                    if (lvl >= ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS) {
                        System.out.printf("[ERROR] semantic level (%d) should be less than config %d: %s\n",
                                lvl, ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS, clLine);
                        System.exit(2);
                    }

                    classSemanticMap.put(args[1], lvl);

                } catch (NumberFormatException ignored) {}
            }
            hasSemantic = true;

        } catch (FileNotFoundException e) {
            System.out.printf("[WARN] %s is not found.\n", ONOSUtil.getONOSClassContextListFilePath());
            hasSemantic = false;
        } catch (IOException e) {
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }


    public static Set<String> getAllClasses(File file, String loc) {
        Set<String> classSet = new HashSet<>();

        if (file.isDirectory()) {
            File[] arr = file.listFiles();
            int len = arr.length;


            for (int i = 0; i < len; ++i) {
                File f = arr[i];
                classSet.addAll(getAllClasses(f, loc + (loc.length() == 0 ? "" : "/") + f.getName()));
            }
        } else {
            if (loc.endsWith(".class")) {
                classSet.add(loc.substring(0, loc.length() - 6));
            }
        }

        return classSet;
    }
}
