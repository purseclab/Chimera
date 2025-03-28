package edu.purdue.cs.pursec.ifuzzer.fuzz.result;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.IntentStateCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;

import java.util.HashMap;
import java.util.Map;

public class IntentScenarioFuzzResult extends ScenarioFuzzResult {
    // add, modify, withdraw, purge, topo-change
    private final Map<String, FuzzActionResult> resultMap = new HashMap<>();

    public boolean addScenarioResult(FuzzScenario fuzzScenario) {
        // addResult first
        super.addScenarioResult(fuzzScenario);

        IntentStateCoverage coverage = fuzzScenario.getIntentStateCoverage();
        if (coverage != null) {
            Map<String, Integer> intentStateChangeMap = coverage.getIntentStateChanges();
            for (String actionCmd : intentStateChangeMap.keySet()) {
                FuzzActionResult fuzzActionResult = resultMap.get(actionCmd);
                if (fuzzActionResult != null)
                    fuzzActionResult.addStateChangeCnt(actionCmd, intentStateChangeMap.get(actionCmd));
            }
        }

        return true;
    }
}
