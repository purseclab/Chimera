package edu.purdue.cs.pursec.ifuzzer.util;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.LogContainerCmd;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.core.command.LogContainerResultCallback;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CommonUtil {
    private static final Logger log = LoggerFactory.getLogger(CommonUtil.class);
    private static final Properties properties;
    private static final DockerClient dockerClient;
    public static final String DevCovOutputFile = "allDevEdge.out";

    private static RuntimeConfig runtimeConfig = new RuntimeConfig();
    private static RuntimeConfig savedRuntimeConfig;

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = TestUtil.class.getClassLoader().getResource("common.properties");
        if (url == null) throw new UncheckedIOException(new FileNotFoundException("common.properties"));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }

        dockerClient = DockerClientBuilder.getInstance().build();
    }


    public static void mkdir(String dirPath) {
        File dir = new File(dirPath);
        if (!dir.exists()) {
            if (!dir.mkdir()) {
                System.err.printf("Cannot create %s\n", dir);
                System.exit(2);
            }
        }
    }

    public static boolean rmdir(String dirPath) {
        File dir = new File(dirPath);
        if (dir.isDirectory()) {
            try {
                FileUtils.deleteDirectory(dir);
                return dir.delete();
            } catch (IOException ignore) {}
        }
        return false;
    }

    public static String mktmpDir() throws IOException {
        String tmpParentPath = properties.getProperty("common.tmp.cov.path");
        mkdir(tmpParentPath);
        return Files.createTempDirectory(Paths.get(tmpParentPath), null).toString();
    }

    public static List<String> runOptiminContainer(String targetPath) {
        CreateContainerResponse container
                = dockerClient.createContainerCmd(properties.getProperty("common.optimin.container.cmd"))
                .withCmd("-e", targetPath)
                .withHostConfig(HostConfig.newHostConfig()
                        .withBinds(Bind.parse(targetPath + ":" + targetPath)))
                .exec();

        dockerClient.startContainerCmd(container.getId()).exec();

        final List<String> logs = new ArrayList<>();
        LogContainerCmd logContainerCmd = dockerClient.logContainerCmd(container.getId());
        logContainerCmd.withStdOut(true)
                .withStdErr(false)
                .withFollowStream(true);

        try {
            logContainerCmd.exec(new LogContainerResultCallback() {
                @Override
                public void onNext(Frame item) {
                    logs.add(item.toString());
                }
            }).awaitCompletion();
        } catch (InterruptedException e) {
            log.error("Interrupted Exception!" + e.getMessage());
        }
        return logs;
    }

    public static String createRuleProtoFilePath(boolean isRelative) {
        String fileName = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"))) + ".proto";
        return getRuleProtoFilePath(fileName, isRelative);
    }

    public static String getRuleProtoFilePath(String fileName, boolean isRelative) {
        String filepath = "";
        if (!isRelative)
            filepath += IFuzzer.rootPath + File.separator;

        return (filepath + IFuzzer.ruleRelativePath + File.separator + fileName);
    }

    public static String getRuleProtoFilePath(String fileName) {
        return getRuleProtoFilePath(fileName, true);
    }


    public static List<File> readAllFiles(String[] fileNames, String parentPath) throws IOException {
        /* read files */
        if (fileNames[0].equals("ALL")) {
            // Get all scenarios
            File scenarioDir = new File(parentPath);
            if (!scenarioDir.isDirectory()) {
                throw new NotDirectoryException("Error: cannot find path " + parentPath);
            }

            try (Stream<Path> paths = Files.walk(Paths.get(parentPath))) {
                return paths.filter(Files::isRegularFile)
                        .map(Path::toFile)
                        .filter(k -> !k.getPath().endsWith(".swp"))
                        .collect(Collectors.toList());
            }
        }

        // Get file
        List<File> files = Arrays.stream(fileNames)
                .map(s -> parentPath + File.separator + s)
                .filter(k -> !k.contains(".."))
                .map(File::new)
                .collect(Collectors.toList());

        List<File> retFiles = new ArrayList<>();
        for (File file : files) {
            if (file.isFile()) {
                // add regular files
                retFiles.add(file);
            } else if (file.isDirectory()) {
                // add regular files in directory

                try (Stream<Path> paths = Files.walk(Paths.get(file.getPath()))) {
                    retFiles.addAll(paths
                            .filter(Files::isRegularFile)
                            .map(Path::toFile)
                            .filter(k -> !k.getPath().endsWith(".swp"))
                            .collect(Collectors.toList()));
                }
            }
        }

        return retFiles;
    }

    public static List<File> getAllChildFiles(String pathStr, String postfix) throws IOException {
        return getAllChildFiles(pathStr, postfix, true);
    }

    public static List<File> getAllChildFiles(String pathStr, String postfix, boolean fileOnly) throws IOException {
        File targetFile = new File(pathStr);

        List<File> retFiles = new ArrayList<>();
        if (targetFile.isFile()) {
            if (pathStr.endsWith(postfix))
                retFiles.add(targetFile);

        } else if (targetFile.isDirectory()) {
            Files.walkFileTree(Paths.get(targetFile.getPath()), EnumSet.of(FileVisitOption.FOLLOW_LINKS), Integer.MAX_VALUE,
                    new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                            if (!fileOnly || attrs.isRegularFile()) {
                                if (file.getFileName().endsWith(".swp"))
                                    return FileVisitResult.CONTINUE;

                                if (postfix == null || file.getFileName().endsWith(postfix))
                                    retFiles.add(file.toFile());
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        }

        return retFiles;
    }

    public static void saveRuntimeConfig() {
        savedRuntimeConfig = runtimeConfig.clone();
    }

    public static void restoreRuntimeConfig() {
        runtimeConfig = savedRuntimeConfig;
        savedRuntimeConfig = null;
    }

    public static void multiplyWaitTimes(int mul) {
        runtimeConfig.intentCheckIntervalMs = ConfigConstants.CONFIG_INTENT_CHECK_INTERVAL_MS * mul;
        runtimeConfig.intentWaitTimeout = ConfigConstants.CONFIG_INTENT_WAIT_TIMEOUT * mul;
        runtimeConfig.flowCheckIntervalMs = ConfigConstants.CONFIG_FLOW_CHECK_INTERVAL_MS * mul;
        runtimeConfig.flowWaitTimeoutSec = ConfigConstants.CONFIG_FLOW_WAIT_TIMEOUT_SEC * mul;
        runtimeConfig.p4PacketWaitMs = ConfigConstants.CONFIG_P4_PACKET_WAIT_MS * mul;
        runtimeConfig.onosInterfaceWaitIntervalMs = ConfigConstants.CONFIG_ONOS_INTERFACE_WAIT_INTERVAL_MS * mul;
        runtimeConfig.onosInterfaceWaitTimeoutMs = ConfigConstants.CONFIG_ONOS_INTERFACE_WAIT_TIMEOUT_MS * mul;
    }

    public static int getRuntimeConfigIntentCheckIntervalMs() {
        return runtimeConfig.intentCheckIntervalMs;
    }

    public static int getRuntimeConfigIntentWaitTimeout() {
        return runtimeConfig.intentWaitTimeout;
    }

    public static int getRuntimeConfigFlowCheckIntervalMs() {
        return runtimeConfig.flowCheckIntervalMs;
    }

    public static int getRuntimeConfigFlowWaitTimeoutSec() {
        return runtimeConfig.flowWaitTimeoutSec;
    }

    public static int getRuntimeConfigP4PacketWaitMs() {
        return runtimeConfig.p4PacketWaitMs;
    }

    public static int getRuntimeConfigOnosInterfaceWaitIntervalMs() {
        return runtimeConfig.onosInterfaceWaitIntervalMs;
    }

    public static int getRuntimeConfigOnosInterfaceWaitTimeoutMs() {
        return runtimeConfig.onosInterfaceWaitTimeoutMs;
    }

    public static boolean isRuntimeConfigTTFMode() {
        return runtimeConfig.ttfMode;
    }

    public static void setRuntimeConfigTTFMode(boolean ttfMode) {
        runtimeConfig.ttfMode = ttfMode;
    }

    public static boolean isRuntimeConfigTestGenMode() {
        return runtimeConfig.testGenMode;
    }

    public static void setRuntimeConfigTestGenMode(boolean runtimeConfigTestGenMode) {
        runtimeConfig.testGenMode = runtimeConfigTestGenMode;
    }

    public static boolean isRuntimeConfigApplyDiffP4Rules() {
        return runtimeConfig.applyDiffP4Rules;
    }

    public static void setRuntimeConfigApplyDiffP4Rules(boolean runtimeConfigApplyDiffP4Rules) {
        runtimeConfig.applyDiffP4Rules = runtimeConfigApplyDiffP4Rules;
    }

    public static void setRuntimeConfigFlowWaitTimeoutSec(int runtimeConfigFlowWaitTimeoutSec) {
        runtimeConfig.flowWaitTimeoutSec = runtimeConfigFlowWaitTimeoutSec;
    }
}