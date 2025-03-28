package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class CoverageUpdateInfo {
    private final Map<String, Coverage> hasUpdatedMap = new HashMap<>();

    public void hasUpdated(String covName, Coverage coverage) {
        hasUpdatedMap.put(covName, coverage);
    }

    public Coverage getCoverage(String covName) {
        return hasUpdatedMap.get(covName);
    }

    public Set<String> getAllUpdatedCoverageNames() {
        return hasUpdatedMap.keySet();
    }

    public void merge(CoverageUpdateInfo that) {
        for (String covName : that.hasUpdatedMap.keySet()) {
            if (!this.hasUpdatedMap.containsKey(covName)) {
                this.hasUpdatedMap.put(covName, that.hasUpdatedMap.get(covName));
            } else {
                Coverage totalCov = this.hasUpdatedMap.get(covName);
                totalCov.updateCoverage(that.hasUpdatedMap.get(covName));
            }
        }
        hasUpdatedMap.putAll(that.hasUpdatedMap);
    }

    public boolean isUpdated() {
        return !hasUpdatedMap.isEmpty();
    }

    public boolean isUpdated(String covName) {
        return hasUpdatedMap.containsKey(covName);
    }

    @Override
    public String toString() {
        return hasUpdatedMap.keySet().stream().sorted().collect(Collectors.joining());
    }
}
