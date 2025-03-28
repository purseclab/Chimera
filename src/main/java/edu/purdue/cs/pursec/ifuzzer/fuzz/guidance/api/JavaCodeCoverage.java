package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.jacoco.core.analysis.*;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataStore;
import org.jacoco.core.data.SessionInfoStore;
import org.jacoco.core.tools.ExecFileLoader;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.*;

public class JavaCodeCoverage extends CodeCoverage {
    private final static int BRANCH_HIT_IDX    = 0;
    private final static int BRANCH_MAX_IDX    = 1;
    private final static int BRANCH_ALL_IDX    = 2;
    private final static int INST_HIT_IDX      = 3;
    private final static int INST_MAX_IDX      = 4;
    private final static int INST_ALL_IDX      = 5;
    private final static int COUNTER_MAX_IDX   = 6;

    private ExecFileLoader loader;
//    private byte[] globalTraceBits = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
    // branch covered, branch total, inst covered, inst total
//    private Map<String, List<Integer>> globalCountersPerMethod;
    private int[] methodCounter = new int[COUNTER_MAX_IDX];
    private int[] classpathCounter = new int[COUNTER_MAX_IDX];
    // class has semantic info
    private int[][] classCounter = new int[ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][COUNTER_MAX_IDX];
    private int totalCnt, hitCnt;

    public JavaCodeCoverage() {}

    public JavaCodeCoverage(JavaCodeCoverage coverage) {
        this.updateCoverage(coverage);
    }

    @Override
    public JavaCodeCoverage deepCopy() {
        JavaCodeCoverage newCov = new JavaCodeCoverage();

        // 1. Create empty newLoader
        ExecFileLoader newLoader  = new ExecFileLoader();
        ExecutionDataStore dataStore = newLoader.getExecutionDataStore();
        SessionInfoStore infoStore = newLoader.getSessionInfoStore();

        // 2. Store all info of this.loader into newLoader
        this.loader.getExecutionDataStore().getContents().forEach(dataStore::put);
        this.loader.getSessionInfoStore().getInfos().forEach(infoStore::visitSessionInfo);

        // 3. copy metadata instead of calling analyze()
        newCov.loader = newLoader;
        newCov.methodCounter = this.methodCounter.clone();
        newCov.classpathCounter = this.classpathCounter.clone();
        newCov.classCounter = this.classCounter.clone();
        newCov.totalCnt = this.totalCnt;
        newCov.hitCnt = this.hitCnt;

        return newCov;
    }

    public synchronized boolean applyLoader(ExecFileLoader loader) {
        if (traceBits[0] > 0) {
            this.initTraceBits(ConfigConstants.COVERAGE_MAP_SIZE);
            for (int i = 0; i < COUNTER_MAX_IDX; i++) {
                methodCounter[i] = 0;
                classpathCounter[i] = 0;
            }
            classCounter = new int[ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][COUNTER_MAX_IDX];
        }

        if (this.loader == null) {
            this.loader = loader;
        } else {
            ExecutionDataStore dataStore = this.loader.getExecutionDataStore();
            SessionInfoStore infoStore = this.loader.getSessionInfoStore();

            // TODO: fix OOM error in JavaCodeCoverage. Loader simply uses ArrayList
            loader.getExecutionDataStore().getContents().forEach(dataStore::put);
            loader.getSessionInfoStore().getInfos().forEach(infoStore::visitSessionInfo);
        }

        int prevHitCount = getBranchHitCount();
        analyze(null);
        int curHitCount = getBranchHitCount();

        return (prevHitCount < curHitCount);
    }

    @Override
    public boolean updateCoverage(@Nullable Coverage that) {
        // 1. update traceBits
        boolean updated = super.updateCoverage(that);

        if (!(that instanceof JavaCodeCoverage))
            return false;

        // Reduce calling loader updates
        if (!updated)
            return false;

        JavaCodeCoverage codeThat = (JavaCodeCoverage)that;
        // 2. update Jacoco Loader
        int prevHitCount = getBranchHitCount();
        applyLoader(codeThat.loader);
        int curHitCount = getBranchHitCount();

        return (prevHitCount < curHitCount);
    }

    public synchronized void diffCoverage(JavaCodeCoverage that) {
        if (this.loader == null) {
            this.loader = that.loader;
        } else {
            ExecutionDataStore dataStore = this.loader.getExecutionDataStore();
            SessionInfoStore infoStore = this.loader.getSessionInfoStore();

            for (ExecutionData data : dataStore.getContents()) {
                if (!that.loader.getExecutionDataStore().contains(data.getName())) {
                    dataStore.subtract(data);
                }
            }

            // XXX: fix it
            that.loader.getSessionInfoStore().getInfos().forEach(infoStore::visitSessionInfo);
        }

        analyze(null);
    }

    public int getBranchHitCount() {
        return methodCounter[BRANCH_HIT_IDX];
    }

    public int getInstructionHitCount() {
        return methodCounter[INST_HIT_IDX];
    }

    public ExecFileLoader getLoader() {
        return loader;
    }

    public static String getProportionStatsHeader() {
        StringBuilder builder = new StringBuilder();
        builder.append("# time(ms), totalHit%, Hit%, covered1(all%, br%, inst%), ..., covered7, etc.\n");
        return builder.toString();
    }

    public static String getStatsHeader() {
        StringBuilder builder = new StringBuilder();
        if (IFuzzer.hasSemantic)
            builder.append("# time(ms), hit, total, interesting(branchHit, branchAll, instHit, instAll), covered1, ..., covered7, covered0");
        else
            builder.append("# time(ms), hit, total, (method, class, classpath) x (branchHit, branchAll, instHit, instAll)");
        return builder.toString();
    }

    public String getProportionStatsString() {

        StringBuilder builder = new StringBuilder();
        builder.append(System.currentTimeMillis());
        builder.append(", ");
        builder.append((hitCnt * 100.0f) / totalCnt);
        builder.append("%, ");
        builder.append(((methodCounter[BRANCH_HIT_IDX] + methodCounter[INST_HIT_IDX]) * 100.0f)
                / (methodCounter[BRANCH_ALL_IDX] + methodCounter[INST_ALL_IDX]));
        builder.append("%, ");
        builder.append(((methodCounter[BRANCH_HIT_IDX]) * 100.0f) / methodCounter[BRANCH_ALL_IDX]);
        builder.append("%, ");
        builder.append(((methodCounter[INST_HIT_IDX]) * 100.0f) / methodCounter[INST_ALL_IDX]);
        builder.append("%");
        for (int i = 1; i <= ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS; i++) {
            int idx = i % ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS;
            builder.append(", ");
            builder.append(((classCounter[idx][BRANCH_HIT_IDX] + classCounter[idx][INST_HIT_IDX]) * 100.0f)
                    / (classCounter[idx][BRANCH_ALL_IDX] + classCounter[idx][INST_ALL_IDX]));
            builder.append("%, ");
            builder.append((classCounter[idx][BRANCH_HIT_IDX] * 100.0f) / classCounter[idx][BRANCH_ALL_IDX]);
            builder.append("%, ");
            builder.append((classCounter[idx][INST_HIT_IDX] * 100.0f) / classCounter[idx][INST_ALL_IDX]);
            builder.append("%");
        }
        return builder.toString();
    }

    public String getStatsString() {
        return getStatsString(true);
    }

    public String getStatsString(boolean printTime) {
        StringBuilder builder = new StringBuilder();
        if (printTime) {
            builder.append(System.currentTimeMillis());
            builder.append(", ");
        }
        builder.append(hitCnt);
        builder.append(", ");
        builder.append(totalCnt);

        for (int i = 0; i < COUNTER_MAX_IDX; i++) {
            builder.append(", ");
            builder.append(methodCounter[i]);
        }

        if (IFuzzer.hasSemantic) {
            for (int i = 1; i <= ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS; i++) {
                for (int j = 0; j < COUNTER_MAX_IDX; j++) {
                    builder.append(", ");
                    builder.append(classCounter[i % ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][j]);
                }
            }
        } else {
            for (int i = 0; i < COUNTER_MAX_IDX; i++) {
                builder.append(", ");
                builder.append(classCounter[0][i]);
            }
            for (int i = 0; i < COUNTER_MAX_IDX; i++) {
                builder.append(", ");
                builder.append(classpathCounter[i]);
            }
        }
        return builder.toString();
    }

    private int getSemanticLevel(String className) {
        if (!IFuzzer.hasSemantic)
            return 0;

        String matchedPackage = "";
        for (String pkg : IFuzzer.classSemanticMap.keySet()) {
            if (className.startsWith(pkg + "/") &&
                    pkg.length() > matchedPackage.length()) {
                matchedPackage = pkg;
            }
        }

        return IFuzzer.classSemanticMap.getOrDefault(matchedPackage, 0);
    }

    /**
     *
     * @param methodKey: "class: name(args,...)return"
     * @return
     */
    private int getSemanticLevelFromMethodKey(String methodKey) {
        return getSemanticLevel(methodKey.split(":")[0]);
    }

    public synchronized void analyze(PrintStream out) {

        // Fill traceBits
        traceBits[0] = 1;
        for (int i = 1; i < this.getMapSize(); i++)
            traceBits[i] = 0;

        boolean analyzeClassOnly = true;

        // Class-aware Coverage
        if (IFuzzer.classfiles != null && IFuzzer.methodBitmap != null && IFuzzer.classpathMap != null) {
            analyzeClassOnly = false;

            try {
                /* Analyze */
                final CoverageBuilder builder = new CoverageBuilder();
                final Analyzer analyzer = new Analyzer(this.loader.getExecutionDataStore(), builder);

                Set<String> analyzedPath = new HashSet<>();
                for (ExecutionData data : this.loader.getExecutionDataStore().getContents()) {
                    // Skip classes which are not interesting
                    String path = IFuzzer.classpathMap.get(data.getName());
                    if (path != null && path.length() > 0 && !analyzedPath.contains(path)) {
//                        System.out.printf("### analyze %s(%s)\n", data.getName(), path);
                        analyzer.analyzeAll(new File(path));
                        analyzedPath.add(path);
                    }
                }

                final IBundleCoverage bundle = builder.getBundle("sample");
                int methodCnt = 0, classCnt = 0;

                /* fill coverageMap */
                for (IPackageCoverage packageCoverage : bundle.getPackages()) {

                    if (out == null) {
                        classpathCounter[BRANCH_HIT_IDX] += packageCoverage.getBranchCounter().getCoveredCount();
                        classpathCounter[BRANCH_MAX_IDX] += packageCoverage.getBranchCounter().getTotalCount();
                        classpathCounter[BRANCH_ALL_IDX] += packageCoverage.getBranchCounter().getTotalCount();
                        classpathCounter[INST_HIT_IDX] += packageCoverage.getInstructionCounter().getCoveredCount();
                        classpathCounter[INST_MAX_IDX] += packageCoverage.getInstructionCounter().getTotalCount();
                        classpathCounter[INST_ALL_IDX] += packageCoverage.getInstructionCounter().getTotalCount();
                    }

                    for (IClassCoverage classCoverage : packageCoverage.getClasses()) {
                        String className = classCoverage.getName();
                        if (className == null)
                            continue;

                        int lvl = getSemanticLevel(className);

                        boolean isInteresting = P4Util.isInteresting(className);

                        // Calculate semantic counter (class-level)
                        if (out == null) {
                            classCounter[lvl][BRANCH_HIT_IDX] += classCoverage.getBranchCounter().getCoveredCount();
                            classCounter[lvl][BRANCH_MAX_IDX] += isInteresting ?
                                    classCoverage.getBranchCounter().getTotalCount() :
                                    classCoverage.getBranchCounter().getCoveredCount();
                            classCounter[lvl][BRANCH_ALL_IDX] += classCoverage.getBranchCounter().getTotalCount();
                            classCounter[lvl][INST_HIT_IDX] += classCoverage.getInstructionCounter().getCoveredCount();
                            classCounter[lvl][INST_MAX_IDX] += isInteresting ?
                                    classCoverage.getInstructionCounter().getTotalCount() :
                                    classCoverage.getInstructionCounter().getCoveredCount();
                            classCounter[lvl][INST_ALL_IDX] += classCoverage.getInstructionCounter().getTotalCount();
                        }

                        if (IFuzzer.hasSemantic && lvl == 0 && ConfigConstants.CONFIG_ENABLE_CODE_COVERAGE_FILTER)
                            continue;

                        classCnt ++;

                        // Get counter per method
                        for (IMethodCoverage methodCoverage : classCoverage.getMethods()) {
                            if (methodCoverage.getName() == null)
                                continue;

                            methodCnt ++;

                            String key = JavaNames.getKeyFromMethod(classCoverage.getName(),
                                    methodCoverage.getName(), methodCoverage.getDesc());

                            /* fill bitmap */
                            int hashId = JavaNames.getHash(key, ConfigConstants.COVERAGE_MAP_SIZE);
                            if (IFuzzer.methodBitmap[hashId]) {
                                traceBits[hashId] |= hobFromInt(methodCoverage.getBranchCounter().getCoveredCount());
                            }

                            if (IFuzzer.methodSet.contains(key)) {
                                if (out != null) {
                                    out.printf("%s: %d\n", key, methodCoverage.getBranchCounter().getCoveredCount());
                                } else {
                                    // Calculate interesting counter in method-level
                                    methodCounter[BRANCH_HIT_IDX] += methodCoverage.getBranchCounter().getCoveredCount();
                                    methodCounter[BRANCH_MAX_IDX] += isInteresting ?
                                            methodCoverage.getBranchCounter().getTotalCount() :
                                            methodCoverage.getBranchCounter().getCoveredCount();
                                    methodCounter[BRANCH_ALL_IDX] += methodCoverage.getBranchCounter().getTotalCount();
                                    methodCounter[INST_HIT_IDX] += methodCoverage.getInstructionCounter().getCoveredCount();
                                    methodCounter[INST_MAX_IDX] += isInteresting ?
                                            methodCoverage.getInstructionCounter().getTotalCount() :
                                            methodCoverage.getInstructionCounter().getCoveredCount();
                                    methodCounter[INST_ALL_IDX] += methodCoverage.getInstructionCounter().getTotalCount();
                                }
                            }
                        }
                    }
                }

//                System.out.printf("[INFO] %d classes & %d methods\n", classCnt, methodCnt);

            } catch (IOException e) {
                e.printStackTrace();
                analyzeClassOnly = true;
            }
        }

        int localTotalCnt = 0;
        int localHitCnt = 0;

        for (ExecutionData data : this.loader.getExecutionDataStore().getContents()) {

            // Skip classes which are not interesting
            if (IFuzzer.classpathMap != null) {
                if (IFuzzer.classpathMap.get(data.getName()) == null)
                    continue;
            }

            int feedbackId = JavaNames.getHash(data.getId(), ConfigConstants.COVERAGE_MAP_SIZE);

            for (boolean probe : data.getProbes()) {
                if (probe) {
                    if (analyzeClassOnly)
                        traceBits[feedbackId]++;
                    localHitCnt ++;
                }
            }
            localTotalCnt += data.getProbes().length;
        }

        if (hitCnt < localHitCnt)
            hitCnt = localHitCnt;

        if (totalCnt < localTotalCnt)
            totalCnt = localTotalCnt;
    }

    public boolean isAnalyzed() {
        return (loader != null);
    }
}
