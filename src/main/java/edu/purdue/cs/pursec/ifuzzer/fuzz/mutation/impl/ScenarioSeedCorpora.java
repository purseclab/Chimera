package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.impl;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.Coverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.P4Coverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedCorporaPolicy;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedScenario;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedSelectionPolicy;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ScenarioSeedCorpora {
    private static final Logger log = LoggerFactory.getLogger(ScenarioSeedCorpora.class);
    private final String coverageDirPath;
    private final int maxThirdKey;
    private final int maxSeeds;
    Random rand = new Random();
    private static final String GLOBAL_KEY1_NAME = "GLOBAL";
    private static final String GLOBAL_KEY2_NAME = "SINGLE";

    /* CORPORA: [COV][RULE][PATH] */
    Map<String, Map<String, Map<Integer, List<SeedScenario>>>> corpora = new ConcurrentHashMap<>();
    Map<String, Map<String, Map<Integer, Integer>>> corporaIdx = new ConcurrentHashMap<>();
    Map<String, Map<String, Map<Integer, Integer>>> corporaCycles = new ConcurrentHashMap<>();

    /* STATS */
    private int totalSeeds = 0;
    private Map<String, List<List<String>>> seedMetadata = new HashMap<>();
    private Map<String, List<String>> seedsPerCov = new TreeMap<>();
    private Map<String, List<String>> seedsPerRules = new HashMap<>();
    private Set<String> matchedRuleSet = new HashSet<>();
    private Map<Integer, List<String>> seedsPerPktType = new HashMap<>();

    public ScenarioSeedCorpora(String coverageDirPath, int maxThirdKey, int maxSeeds) {
        this.coverageDirPath = coverageDirPath;
        this.maxThirdKey = maxThirdKey;
        this.maxSeeds = maxSeeds;
    }

    public boolean hasSeed(String k1, String k2, int k3) {
        if (k1 != null && !seedsPerCov.containsKey(k1))
            return false;

        if (k2 != null && !seedsPerRules.containsKey(k2))
            return false;

        if (k3 >= 0 && k3 < maxThirdKey && !seedsPerPktType.containsKey(k3))
            return false;

        return !corpora.isEmpty();
    }

    public boolean putSeed(String k1, String[] k2, int k3, SeedScenario scenario) {
        if (k2.length == 0)
            return false;

        String localK1 = k1;
        if (ConfigConstants.CONFIG_SEED_CORPORA_POLICY.equals(
                SeedCorporaPolicy.GLOBAL)) {
            localK1 = GLOBAL_KEY1_NAME;
        }

        String localK2 = k2[0];
        // TODO: support k2-2 (i.e. H(matched)) in general way
        if (k2.length > 1)
            matchedRuleSet.add(k2[1]);

        int localK3 = k3;
        switch (ConfigConstants.CONFIG_P4_SEED_CORPUS_POLICY) {
            case SINGLE:
                localK2 = GLOBAL_KEY2_NAME;
                localK3 = maxThirdKey;
                break;
            case UNIQUE_RULE:
                localK3 = maxThirdKey;
                break;
            case UNIQUE_PACKET:
                localK2 = GLOBAL_KEY2_NAME;
                break;
            default:
                break;
        }

        return internalPutSeed(k1, localK1, k2[0], localK2, k3, localK3, scenario);
    }

    boolean internalPutSeed(String k1, String localK1, String k2, String localK2,
                                   int k3, int localK3, SeedScenario scenario) {
        List<SeedScenario> corpusList = corpora.computeIfAbsent(localK1, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(localK2, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(localK3, k -> new LinkedList<>());

        if (!corpusList.contains(scenario)) {
            log.debug("putSeed: {}/{}/{} - [{}] {}", k1, k2, k3,
                    scenario.getScenario().getName(),
                    scenario.getUuid());
            corpusList.add(scenario);
            if (ConfigConstants.CONFIG_SEED_SELECTION_POLICY.equals(SeedSelectionPolicy.LRU)) {
                corporaIdx.computeIfAbsent(localK1, k -> new ConcurrentHashMap<>())
                        .computeIfAbsent(localK2, k -> new ConcurrentHashMap<>())
                        .put(localK3, -1);
            }

            // Update stats
            String seedId = scenario.getUuid().toString();
            totalSeeds ++;
            seedsPerCov.computeIfAbsent(k1, k -> new ArrayList<>()).add(seedId);
            seedsPerRules.computeIfAbsent(k2, k -> new ArrayList<>()).add(seedId);
            seedsPerPktType.computeIfAbsent(k3, k -> new ArrayList<>()).add(seedId);
            seedMetadata.computeIfAbsent(seedId, k -> new ArrayList<>()).add(List.of(k1, k2, String.valueOf(k3)));
            return true;
        }

        return false;
    }

    public SeedScenario getNextSeed(String secondKey) {
        // Get corpus randomly
        String[] k1List = corpora.keySet().toArray(new String[0]);
        String k1 = k1List[rand.nextInt(k1List.length)];

        String k2;
        if (secondKey == null || !corpora.get(k1).containsKey(secondKey)) {
            String[] k2List = corpora.get(k1).keySet().toArray(new String[0]);
            k2 = k2List[rand.nextInt(k2List.length)];
        } else {
            k2 = secondKey;
        }

        Integer[] k3List = corpora.get(k1).get(k2).keySet().toArray(new Integer[0]);
        int k3 = k3List[rand.nextInt(k3List.length)];

        // Get scenario in corpus based on policy (RR/LRU)
        List<SeedScenario> corpus = corpora.get(k1).get(k2).get(k3);
        if (maxSeeds > 0 && corpus.size() > maxSeeds) {
            try {
                List<SeedScenario> minCorpus = minimizeSeed(corpus, k1);
                if (minCorpus != null) {
                    replaceCorpus(k1, k2, k3, minCorpus);
                    corpus = minCorpus;
                }
            } catch (IOException e) {
                log.warn("Cannot minimize seed corpus {}:{}:{} - {}", k1, k2, k3,
                        e.getMessage());
            }
        }

        int curIdx = corporaIdx.computeIfAbsent(k1, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(k2, k -> new ConcurrentHashMap<>())
                .getOrDefault(k3, -1);

        switch (ConfigConstants.CONFIG_SEED_SELECTION_POLICY) {
            /* LRU may focus on recent stored seeds */
            case LRU:
            {
                if (curIdx < 0) {
                    curIdx = corpus.size();
                }
                curIdx--;
                if (curIdx < 0) {
                    curIdx = corpus.size() - 1;
                    corporaCycles.computeIfAbsent(k1, k -> new ConcurrentHashMap<>())
                            .computeIfAbsent(k2, k -> new ConcurrentHashMap<>())
                            .compute(k3, (k, v) -> (v == null) ? 1 : v+1);
                }
                break;
            }
            case RR:
            default:
                curIdx = (curIdx + 1) % corpus.size();
                if (curIdx == 0) {
                    corporaCycles.computeIfAbsent(k1, k -> new ConcurrentHashMap<>())
                            .computeIfAbsent(k2, k -> new ConcurrentHashMap<>())
                            .compute(k3, (k, v) -> (v == null) ? 0 : v+1);
                }
                break;
        }
        corporaIdx.get(k1).get(k2).put(k3, curIdx);
        return corpus.get(curIdx);
    }

    /*
     * statString() will give following info:
     * [1] Total num seeds
     * [2] Total num rule sets
     * [3] Total num matched rule sets!
     * [4] Total num seeds per coverage (onos/bmv2/p4)
     * [5] Total num seeds for each packet type (6 types..)
     * [6] Min/Median/Max num seeds for each rule set
     */
    public String statString(List<String> covPrefixList) {

        StringBuilder sb = new StringBuilder();
        // [1] Total num seeds
        sb.append(totalSeeds).append(", ");
        // [2] Total num rule sets
        sb.append(seedsPerRules.values().stream()
                .map(HashSet::new)
                .filter(k -> !k.isEmpty()).count()).append(", ");

        // [3] (exp) Total num matched rule sets
        sb.append(matchedRuleSet.size()).append(", ");

        // [4] Total num seeds per coverage (onos/bmv2/p4)
        Map<String, Long> seedsPerCovMap = new LinkedHashMap<>();
        for (String covName : seedsPerCov.keySet()) {
            String covPrefix = covName.substring(0, Integer.min(covName.length(), 2));
            if (covPrefixList == null || covPrefixList.contains(covPrefix))
                seedsPerCovMap.merge(covPrefix, (long) seedsPerCov.get(covName).size(), Long::sum);
        }

        if (covPrefixList == null) {
            seedsPerCovMap.values().forEach(k -> sb.append(k).append(", "));
        } else {
            for (String covPrefix : covPrefixList) {
                sb.append(seedsPerCovMap.get(covPrefix)).append(", ");
            }
        }

        // [5] Total num seeds for each packet type (6 types..)
        for (int i = 0; i < maxThirdKey; i++) {
            if (seedsPerPktType.containsKey(i)) {
                sb.append(new HashSet<>(seedsPerPktType.get(i)).size()).append(", ");
            } else {
                sb.append(0).append(", ");
            }
        }

        // [6] Min/Median/Max num seeds for each rule set
        List<Integer> seedsPerRuleList = seedsPerRules.values().stream()
                .map(HashSet::new)
                .map(Set::size)
                .filter(k -> k > 0)
                .sorted()
                .collect(Collectors.toList());
        int listLen = seedsPerRuleList.size();
        if (listLen == 0) {
            for (int i = 0; i < 3; i++)
                sb.append(0).append(", ");

        } else {
            // min
            sb.append(seedsPerRuleList.get(0)).append(", ");
            // median
            int middleIdx = listLen / 2;
            if (listLen % 2 == 1)
                sb.append(seedsPerRuleList.get(middleIdx)).append(", ");
            else
                sb.append((seedsPerRuleList.get(middleIdx - 1) +
                        seedsPerRuleList.get(middleIdx)) / 2).append(", ");
            // max
            sb.append(seedsPerRuleList.get(listLen - 1));
        }

        return sb.toString();
    }

    void replaceCorpus(String k1, String k2, int k3, List<SeedScenario> newCorpus) {
        List<SeedScenario> corpus = corpora.get(k1).get(k2).get(k3);
        log.info("Corpus {}:{}:{} has minimized: {} -> {}",
                k1, k2, k3,
                corpus.size(), newCorpus.size());
        corpora.get(k1).get(k2).put(k3, newCorpus);
        corporaIdx.computeIfAbsent(k1, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(k2, k -> new ConcurrentHashMap<>())
                .put(k3, -1);

        /*
         * Update statistics.
         * 1) Recalculate counter - impossible
         *   - Global corpora policy abstracts seeds from different coverage.
         *   - After minimization, it is impossible to get coverage seed count from global corpus.
         * 2) Subtract removed strings - probably buggy
         *   - Remain duplicates in stats, then remove target key set.
         *   - If key is global, key cannot differentiate coverages as well.
         * 3) Maintain UUID:k1,k2,k3 regardless of localK1,localK2,localK3
         *   - Check localK1,localK2,localK3 with UUID:k1,k2,k3.
         */
        Set<String> origSeedUuidSet = corpus.stream().map(k -> k.getUuid().toString())
                .collect(Collectors.toSet());
        Set<String> newSeedUuidSet = newCorpus.stream().map(k -> k.getUuid().toString())
                .collect(Collectors.toSet());
        origSeedUuidSet.removeAll(newSeedUuidSet);
        resetStats(k1, k2, k3, origSeedUuidSet);
    }

    private void resetStats(String localK1, String localK2, int localK3, Set<String> removedSeedUuidSet) {
        totalSeeds -= removedSeedUuidSet.size();

        for (String seedId : removedSeedUuidSet) {
            List<List<String>> keyLists = seedMetadata.get(seedId);

            // Compare (1) global keyLists and (2) localKeys in corpora
            Iterator<List<String>> keyListIter = keyLists.iterator();
            while (keyListIter.hasNext()) {
                List<String> keyList = keyListIter.next();
                if (keyList.size() != 3) {
                    log.error("Wrong metadata for {}", seedId);
                    continue;
                }

                if (!localK1.equals(GLOBAL_KEY1_NAME) && !keyList.get(0).equals(localK1))
                    continue;

                if (!localK2.equals(GLOBAL_KEY2_NAME) && !keyList.get(1).equals(localK2))
                    continue;

                if (localK3 < maxThirdKey && !keyList.get(2).equals(String.valueOf(localK3)))
                    continue;

                seedsPerCov.get(keyList.get(0)).remove(seedId);
                seedsPerRules.get(keyList.get(1)).remove(seedId);
                seedsPerPktType.get(Integer.valueOf(keyList.get(2))).remove(seedId);
                keyListIter.remove();
            }
        }
    }

    private List<SeedScenario> minimizeSeed(List<SeedScenario> origScenarioList, String hint)
            throws IOException {
        File coverageDir = new File(coverageDirPath);
        if (!coverageDir.isDirectory()) {
            log.warn("{} is not directory", coverageDirPath);
            return null;
        }

        File covHintFile = new File(coverageDirPath, hint);
        List<String> covNames = new ArrayList<>();
        if (covHintFile.isDirectory()) {
            covNames.add(hint);
        } else {
            String[] coverageFiles = coverageDir.list((dir, name) -> new File(dir, name).isDirectory());
            if (coverageFiles != null)
                covNames.addAll(Arrays.asList(coverageFiles));
        }

        if (covNames.isEmpty()) {
            log.warn("{} does not have coverages", coverageDirPath);
            return null;
        }

        Map<String, String> covTmpPathMap = new HashMap<>();
        Iterator<String> it = covNames.iterator();
        while (it.hasNext()) {
            String covName = it.next();
            File covDir = new File(coverageDirPath + File.separator + covName);
            if (!covDir.exists()) {
                it.remove();
                continue;
            }
            String tmpPath = CommonUtil.mktmpDir();
            covTmpPathMap.put(covName, tmpPath);
        }

        // Get all dumped scenarios
        Map<String, SeedScenario> scenarioMap = new HashMap<>();
        for (SeedScenario origScenario : origScenarioList) {
            boolean isCopied = false;
            for (String covName : covNames) {
                String covFilePath = coverageDirPath + File.separator + covName +
                        File.separator + origScenario.getUuid();
                File covFile = new File(covFilePath);
                if (!covFile.exists())
                    continue;

                Coverage fileCov;
                // TODO: minimize seeds based on rule trace/path
                if (covName.startsWith("R"))
                    continue;
                else if (covName.startsWith("P"))
                    fileCov = P4Coverage.of(covFilePath);
                else
                    fileCov = CodeCoverage.of(covFilePath);

                if (fileCov == null)
                    continue;

                fileCov.storeCoverageTtf(covTmpPathMap.get(covName) + File.separator +
                        origScenario.getUuid());
                isCopied = true;
            }

            if (isCopied)
                scenarioMap.put(origScenario.getUuid().toString(), origScenario);
        }

        // Execute optimin on tmpPath
        Set<String> minUuidSet = new HashSet<>();
        for (String covName : covNames) {
            String tmpPath = covTmpPathMap.get(covName);
            List<String> minUuidList = executeOptimin(tmpPath);
            minUuidSet.addAll(minUuidList);
//            if (!CommonUtil.rmdir(tmpPath))
//                log.warn("{} is not deleted", tmpPath);
        }

        return minUuidSet.stream().map(scenarioMap::get).collect(Collectors.toList());
    }

    private List<String> executeOptimin(String targetPath) {
        List<String> resultStr = CommonUtil.runOptiminContainer(targetPath);

        return resultStr.stream()
                .map(k -> {
                    if (k.startsWith("STDOUT: "))
                        k = k.substring("STDOUT: ".length());
                    return k;
                })
                .map(String::trim)
                .filter(k -> (!k.isEmpty() && !k.startsWith("[")))
                .skip(1)
                .collect(Collectors.toList());
    }
}
