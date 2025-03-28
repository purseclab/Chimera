package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.TableEntry;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.PathCoverage;

import javax.annotation.Nullable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class RulePathCoverage extends Coverage {
    private final String ruleKey;
    private final Map<String, String> pathComponents;
    private final Set<String> coveredPathSet;
    private final Map<String, BigInteger> totalPathMap;
    private final String deviceId;

    public RulePathCoverage(String deviceId, P4Testgen.TestCase testCase) {
        this.deviceId = deviceId;
        this.pathComponents = new LinkedHashMap<>();
        this.coveredPathSet = new HashSet<>();
        this.totalPathMap = new LinkedHashMap<>();

        // get valid entries first.
        char bPrefix = 'A';
        StringBuilder sb = new StringBuilder();
        for (PathCoverage pathCov : testCase.getPathCovList()) {
            String blockName = pathCov.getBlockName();
            pathComponents.put(blockName, String.valueOf(bPrefix));
            totalPathMap.put(blockName, new BigInteger(pathCov.getPathSize().toByteArray()));
            sb.append(bPrefix).append(new BigInteger(pathCov.getPathVal().toByteArray()));
            bPrefix++;
        }
        coveredPathSet.add(sb.toString());
        ruleKey = P4Util.genHashCode(testCase.getEntitiesList());
    }

    public RulePathCoverage(RulePathCoverage cov) {
        this.deviceId = cov.deviceId;
        this.ruleKey = cov.ruleKey;
        this.pathComponents = new LinkedHashMap<>(cov.pathComponents);
        this.totalPathMap = new LinkedHashMap<>(cov.totalPathMap);
        this.coveredPathSet = new HashSet<>(cov.coveredPathSet);
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getRuleKey() {
        return ruleKey;
    }

    public int getPathCount() {
        return coveredPathSet.size();
    }

    public String getStatsString(boolean printTime) {
        StringBuilder sb = new StringBuilder();
        if (printTime) {
            sb.append(System.currentTimeMillis());
            sb.append(", ");
        }
        sb.append(deviceId);
        sb.append(", ");
        sb.append(this.getPathCount());

        return sb.toString();
    }

    @Override
    public void storeCoverageMap(String filePath) {
//        try (DataOutputStream fw = new DataOutputStream(Files.newOutputStream(Paths.get(filePath)))) {
//            fw.writeCh
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    @Override
    public void storeCoverageTtf(PrintStream fw) {
//        try (PrintStream fw = new PrintStream(filePath)) {
//            List<Integer> pathMapValues = this.coveredPathMap.values().stream()
//                    .map(Set::size)
//                    .collect(Collectors.toList());
//            int i = 0;
//            for (int pathMapSize : pathMapValues) {
//                fw.printf("%d:%d\n", i, pathMapSize);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    @Override
    public boolean updateCoverage(@Nullable Coverage that) {
        if (!(that instanceof RulePathCoverage))
            return false;

        RulePathCoverage covThat = (RulePathCoverage)that;
        if (!this.deviceId.equals(covThat.deviceId))
            return false;

        if (!this.ruleKey.equals(covThat.ruleKey))
            return false;

        int prevPathCount = this.getPathCount();
        this.coveredPathSet.addAll(covThat.coveredPathSet);

        return (this.getPathCount() > prevPathCount);
    }

    @Override
    public boolean hasBitmap() {
        return false;
    }
}
