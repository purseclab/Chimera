package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.P4SeedCorpusPolicy;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedCorporaPolicy;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api.SeedSelectionPolicy;

// TODO: define these values in config.properties
// TODO: make afl_postprocessor to enforce json format
public class ConfigConstants {
    // TODO: refer scenario guidance from scenario json file
    public static final String CONFIG_FUZZING_SCENARIO_GUIDANCE = "P4CodeCovGuidance";
    // public static final String CONFIG_FUZZING_SCENARIO_GUIDANCE = "SingleP4RuleGuidance";
    // public static final String CONFIG_FUZZING_SCENARIO_GUIDANCE = "IntentStateGuidance";
    public static final String CONFIG_FUZZING_INTENT_GUIDANCE = "NoIntentGuidance";
    // public static final String CONFIG_FUZZING_INTENT_GUIDANCE = "TopologyIntentGuidance";
    public static final String CONFIG_FUZZING_PACKET_GUIDANCE = "NoIntentPacketGuidance";
    public static final String CONFIG_FUZZING_P4RULE_GUIDANCE = "ChimeraRuleGuidance";
    // public static final String CONFIG_FUZZING_P4RULE_GUIDANCE = "NoGuidance";
    public static final String CONFIG_FUZZING_P4PACKET_GUIDANCE = "ChimeraPacketGuidance";

    public static final boolean CONFIG_STORE_INITIAL_TESTS_IN_RESULTS = false;
    public static final boolean CONFIG_ACCEPT_INSTALLING_AS_ERROR = true;
    public static final boolean STOPFUZZ_BUG4 = false;
    public static final int CONFIG_INTENT_CHECK_INTERVAL_MS = 250;
    public static final int CONFIG_INTENT_WAIT_TIMEOUT = 9;
    public static final int CONFIG_FLOW_CHECK_INTERVAL_MS = 250;
    public static final int CONFIG_FLOW_WAIT_TIMEOUT_SEC = 2;
    public static final int CONFIG_TOPOLOGY_CHECK_INTERVAL_MS = 1000;
    public static final int CONFIG_TOPOLOGY_WAIT_TIMEOUT = 0;
    public static final int CONFIG_TOPOLOGY_HOST_WAIT_TIMEOUT = 10;
    public static final int CONFIG_MEASURE_STAT_INTERVAL = 5;

    /*
     * CONFIG_FUZZING_MAX_INSTALLED_INTENT:
     *   - 0: no limit in number of installed (TODO: support dp-test for multiple intents)
     *   - 1: allow only single installed intent at a time
     *   - > 2: allow two or more installed intent at a time
     */
    public static final boolean CONFIG_SET_INVALID_AS_SEMANTIC = true;
    public static final boolean CONFIG_ENABLE_STATIC_MIRROR = true;
    public static final int CONFIG_FUZZING_MAX_INSTALLED_INTENT = 0;
    public static final boolean CONFIG_FUZZING_JSON_INVARIANCE = false;
    public static final boolean CONFIG_FUZZING_TYPE_INVARIANCE = false;
    public static final boolean CONFIG_ENABLE_COVERAGE_LOGGING = true;
    public static final boolean CONFIG_RUN_FUZZING_IN_LOCAL = true;
    public static final boolean CONFIG_ENABLE_H2H_HINT_FIELD = false;
    public static final int COVERAGE_MAP_SIZE = 1 << 16;
    public static final boolean CONFIG_ENABLE_SELECTOR = false;
    public static final boolean CONFIG_ENABLE_MUTATE_TOPOLOGY = true;
    public static final boolean CONFIG_FUZZING_HOST_IN_SUBNET = true;
    public static final boolean CONFIG_ENABLE_CODE_COVERAGE_FILTER = true;
    public static final boolean CONFIG_DISABLE_SAME_POINTS_OF_P2P_INTENT = false;
    public static final boolean CONFIG_DP_VERIFY_WITH_DELETION = true;
    public static final boolean CONFIG_TRUNCATE_ACTIONS_AFTER_ERROR = true;
    public static boolean CONFIG_ENABLE_TEST_EACH_ERROR_INTENT = true;
    public static final boolean CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE = true;
    public static final int CONFIG_NUM_CODE_SEMANTIC_LEVELS = 8;
    public static final int CONFIG_PACKET_FUZZING_TIMEOUT = 0;                  /* used by PazzPacketGuidance */
    public static final int CONFIG_PAZZ_PACKET_HEADER_LEN = 32;                 /* used by FlowRuleStore */
    public static final String CONFIG_PAZZ_CONSISTENCY_TESTER_IP = "";
    public static final int CONFIG_ONOS_INTERFACE_WAIT_INTERVAL_MS = 100;
    public static final int CONFIG_ONOS_INTERFACE_WAIT_TIMEOUT_MS = 1000;

    // TODO: set different pipelines for specific devices in the same topology
    // public static final String CONFIG_P4_PIPELINE = "org.onosproject.pipelines.basic";
    // public static final String CONFIG_P4_PIPELINE = "org.onosproject.pipelines.int";
    public static final String CONFIG_P4_PIPELINE = "org.stratumproject.fabric.bmv2";
    // public static final String CONFIG_P4_PIPELINE = "org.stratumproject.fabric-int.bmv2";

    public static final String CONFIG_P4_TESTED_DEVICE_ID = "device:s1";        /* single P4 device */
    // public static final String CONFIG_P4_TESTED_DEVICE_ID = "device:r0";      /* remote P4 device */
    public static final int CONFIG_P4_CONTROLLER_PORT = 255;
    public static final boolean CONFIG_P4_MUTATE_RULE_SYNTAX = false;
    public static final int CONFIG_MAX_FUZZ_RETRY_CNT = 3;
    public static final int CONFIG_P4_FUZZ_PACKET_CNT = 15;
    public static final int CONFIG_P4_PACKET_WAIT_MS = 100;
    public static final int CONFIG_P4_MAX_ALLOW_PORT_NUM = 8;
    public static final int CONFIG_P4_MAX_FUZZ_RETRY_CNT = 10;
    public static final boolean CONFIG_STORE_UNIQUE_ERROR = false;
    public static final boolean CONFIG_STORE_ADD_RULE_ERROR_IN_CORPUS = false;
    public static final boolean CONFIG_STORE_CP_VERIFY_RULE_ERROR_IN_CORPUS = false;
    public static final boolean CONFIG_ENABLE_P4_INVARIANT_CHECK = false;
    public static final boolean CONFIG_SKIP_P4_KNOWN_BUGS = false;
    public static final boolean CONFIG_APPLY_DIFF_P4_RULES = false;     /* experimental */
    public static final boolean CONFIG_STORE_COVERAGE_DATA = false;
    public static final int CONFIG_PERIOD_STORE_CASE_TO_MERGE = 5;
    public static final int CONFIG_MAX_NUM_STORE_CASE_TO_MERGE = 10;
    public static final int CONFIG_SOFT_LIMIT_ENTITIES_CNT = 100;
    public static final SeedSelectionPolicy CONFIG_SEED_SELECTION_POLICY = SeedSelectionPolicy.LRU;
    public static final SeedCorporaPolicy CONFIG_SEED_CORPORA_POLICY = SeedCorporaPolicy.LOCAL;
    public static final P4SeedCorpusPolicy CONFIG_P4_SEED_CORPUS_POLICY = P4SeedCorpusPolicy.SINGLE;
}
