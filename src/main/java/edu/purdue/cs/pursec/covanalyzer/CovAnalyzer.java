package edu.purdue.cs.pursec.covanalyzer;

import com.codahale.metrics.Slf4jReporter.LoggingLevel;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CovAnalyzer {
    private static final boolean DEBUG = false;

    public static Map<String, Long> getCoveredMap(String pathStr) throws IOException {
//        String fileName = CommonUtil.DevCovOutputFile;
        String fileName = ONOSUtil.ONOSCovOutputFile;
        List<File> covFileList = CommonUtil.getAllChildFiles(pathStr, fileName);

        Map<String, Long> coveredBranch = new HashMap<>();
        boolean isDebug = DEBUG;
        for (File covFile : covFileList) {
            String covFilePath = covFile.getAbsolutePath();
            String covDirName = covFilePath.substring(0, covFilePath.length() - fileName.length() - 1);
            String covName = "VM" + covDirName.charAt(covDirName.length() - 1);
            try {
                Scanner scanner = new Scanner(covFile);
                long totalCovered = 0;

                while (scanner.hasNextLine()) {
                    String targetLine = scanner.nextLine();
                    Pattern p = Pattern.compile("[0-9]+$");
                    Matcher m = p.matcher(targetLine);
                    if (m.find()) {
                        String covStr = m.group();
                        String covKey = targetLine.substring(0, targetLine.length() - covStr.length() - 1);
                        long numCovered = Long.parseLong(covStr);
                        coveredBranch.compute(covKey, (k, v) -> (v == null) ? numCovered : Long.max(v, numCovered));
                        totalCovered += numCovered;
                        if (isDebug) {
                            System.err.printf("%s: %d\n", covKey, numCovered);
                            isDebug = false;
                        }
                    } else {
                        System.err.println("[WARN] " + targetLine + " doesn't have covered branches");
                        System.exit(2);
                    }
                }
                //System.out.printf("%s: %d\n", covName, totalCovered);

            } catch (FileNotFoundException e) {
                System.err.println("[WARN] " + e.getMessage());
            }
        }

        if (DEBUG)
            System.out.println("total: " + coveredBranch.values().stream().reduce(0L, Long::sum));

        return coveredBranch;
    }

    private static Long[] getCommonCovered(Long[] covered, int depth, int index) {
        if (depth == 1) {
            if (index >= covered.length)
                return null;
            return Arrays.copyOfRange(covered, index, covered.length);
        }

        List<Long> commonCovered = new ArrayList<>();
        for (int i = index; i < covered.length - 1; i++) {
            Long[] retArr = getCommonCovered(covered, depth - 1, i + 1);
            if (retArr == null)
                continue;
            for (int j = 0; j < retArr.length; j++) {
                commonCovered.add(Long.min(covered[i], retArr[j]));
            }
        }

        return commonCovered.toArray(new Long[0]);
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: CovAnalyzer [targetDir]");
            System.exit(0);
        }

        // Get file
        File targetDir = new File(args[0]);
        if (!targetDir.isDirectory()) {
            System.err.printf("Error: %s is not directory\n", args[0]);
            System.exit(0);
        }

        if (DEBUG)
            System.out.printf("Search %s\n", targetDir.getAbsolutePath());
        Map<String, String> targetPathMap = new HashMap<>();

        try (Stream<Path> paths = Files.find(Paths.get(targetDir.getPath()), 1,
                (p, bfa) -> bfa.isDirectory())) {
            paths.map(Path::toAbsolutePath)
                    .map(Path::toString)
                    .forEach(s -> {
                        String[] tmpStrs = s.split(File.separator);
                        String k = tmpStrs[tmpStrs.length - 1];
                        targetPathMap.put(k, s);
                    });
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        }

        try (Stream<Path> paths = Files.find(Paths.get(targetDir.getPath()), 1,
                (p, bfa) -> bfa.isSymbolicLink())) {
            paths.map(Path::toAbsolutePath)
                    .forEach(path -> {
                        try {
                            Path slPath = path.toRealPath();
                            if (Files.isDirectory(slPath)) {
                                String[] tmpStrs = path.toString().split(File.separator);
                                String k = tmpStrs[tmpStrs.length - 1];
                                targetPathMap.put(k, slPath.toString());
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        }

        targetPathMap.remove("random");

        Map<String, Long> allCoveredMap = new HashMap<>();
        Map<String, Map<String, Long>> coveredBranchMaps = new HashMap<>();
        List<String> targetKeys = new ArrayList<>(targetPathMap.keySet());
        String parentDir = "";
        for (String targetKey : targetKeys) {
            try {
                String targetPath = targetPathMap.get(targetKey);
                if (targetPath.equals(targetDir.getAbsolutePath())) {
                    allCoveredMap = getCoveredMap(targetPath);
                    parentDir = targetKey;
                } else {
                    if (DEBUG)
                        System.out.println("Start Analyzer: " + targetKey);
                    coveredBranchMaps.put(targetKey, getCoveredMap(targetPath));
                }
            } catch (IOException e) {
                System.err.printf(e.getMessage());
            }
        }

        // Remove parent dir
        targetKeys.remove(parentDir);
        Collections.sort(targetKeys);

        // TODO: naive calculation for same method
        Long[] covered = new Long[targetKeys.size()];
        Long[] allCoveredCnt = new Long[1 << targetKeys.size()];
        Long[] coverMethods = new Long[targetKeys.size()];
        Long[] allMethodCnt = new Long[1 << targetKeys.size()];
        Long[] onlyCovered = new Long[targetKeys.size()];
        Long[] onlyMethodCnt = new Long[targetKeys.size()];
        Map<String, Map<String, Long>> onlyCoveredMap = new HashMap<>();

        Arrays.fill(onlyCovered, 0L);
        Arrays.fill(allCoveredCnt, 0L);
        Arrays.fill(allMethodCnt, 0L);
        Arrays.fill(onlyMethodCnt, 0L);

        if (DEBUG)
            System.out.println(targetKeys.size() + " -> " + allCoveredCnt.length);

        for (int i = 0; i < targetKeys.size(); i++) {
            String targetKey = targetKeys.get(i);
            if (targetKey.length() > 3) {
                targetKey = targetKey.substring(0, 1).toUpperCase() + targetKey.substring(1);
            } else {
                targetKey = targetKey.toUpperCase();
            }

            System.out.printf(" %s", targetKey);
        }
        System.out.println();

        // 0, 1, 2 -> 01, 02, 12, 0123
        int isDebug = 0;
        for (String covKey : allCoveredMap.keySet()) {
            boolean doesSkip = true;
            int covIdx = -1;
            // 1. Get all covered for each method
            for (int i = 0; i < targetKeys.size(); i++) {
                covered[i] = coveredBranchMaps.get(targetKeys.get(i))
                        .computeIfAbsent(covKey, v -> 0L);
                coverMethods[i] = covered[i] > 0 ? 1L : 0L;
                if (covered[i] > 0) {
                    doesSkip = false;
                    if (covIdx < 0)
                        covIdx = i;
                    else
                        covIdx = targetKeys.size();
                }
            }

            if (covIdx >= 0 && covIdx < targetKeys.size()) {
                String targetKey = targetKeys.get(covIdx);
//                if (targetKey.equals("fp4")) {
//                    System.out.println(covKey);
//                }
                onlyCovered[covIdx] += covered[covIdx];
                onlyMethodCnt[covIdx] ++;
                onlyCoveredMap.computeIfAbsent(targetKey, k -> new HashMap<>())
                        .put(covKey, covered[covIdx]);
            }

            if (doesSkip)
                continue;

            // 2. Calculate common covered for each method
            List<Long> commonCovered = new ArrayList<>();
            for (int i = 0; i < targetKeys.size(); i++) {
                Long[] retVal = getCommonCovered(covered, i + 1, 0);
                if (retVal == null) {
                    System.out.println("Skip " + covKey);
                    doesSkip = true;
                    break;
                } else {
                    if (isDebug > 0) {
                        for (int j = 0; j < retVal.length; j++)
                            System.out.printf(" %d", retVal[j]);
                        System.out.printf(" (%d)", retVal.length);
                    }
                }
                commonCovered.addAll(List.of(retVal));
            }

            if (doesSkip)
                continue;

            List<Long> commonMethods = new ArrayList<>();
            for (int i = 0; i < targetKeys.size(); i++) {
                Long[] retVal = getCommonCovered(coverMethods, i + 1, 0);
                if (retVal == null) {
                    System.out.println("Skip " + covKey);
                    break;
                }
                commonMethods.addAll(List.of(retVal));
            }
            if (isDebug > 0)
                System.out.println();

            // 3. Sum all common covered for all methods
            for (int i = 0; i < commonCovered.size(); i++) {
                allCoveredCnt[i] += commonCovered.get(i);
                allMethodCnt[i] += commonMethods.get(i);
                if (isDebug > 0) {
                    System.out.printf(" %d", commonCovered.get(i));
                }
            }

            if (isDebug > 0) {
                System.out.println();
                isDebug --;
            }
        }

        for (Long aLong : allCoveredCnt) {
            System.out.printf(" %d", aLong);
        }
        System.out.println();

        for (Long aLong : allMethodCnt) {
            System.out.printf(" %d", aLong);
        }
        System.out.println();

        for (Long aLong : onlyCovered) {
            System.out.printf(" %d", aLong);
        }
        System.out.println();

        for (Long aLong : onlyMethodCnt) {
            System.out.printf(" %d", aLong);
        }
        System.out.println();

        for (String targetKey : onlyCoveredMap.keySet()) {
            Map<String, Long> covKeyMap = onlyCoveredMap.get(targetKey);
            try {
                File targetFile = new File(targetKey + ".txt");
                PrintStream resultOut = new PrintStream(targetFile);
                covKeyMap.forEach((k, v) -> resultOut.println(k + " " + v));
                resultOut.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
