package edu.purdue.cs.pursec.ifuzzer.fuzz.result;

import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;

import java.util.HashMap;
import java.util.Map;

public class ScenarioFuzzResult extends FuzzResult {
    // add, modify, withdraw, purge, topo-change
    private final Map<String, FuzzActionResult> resultMap = new HashMap<>();

    public boolean addScenarioResult(FuzzScenario fuzzScenario) {
        // addResult
        return addResult(fuzzScenario, fuzzScenario.getErrorMsg());
    }

    public boolean addActionResult(FuzzAction fuzzAction) {
        if (!fuzzAction.isExecutable())
            return false;

        FuzzActionResult fuzzActionResult = resultMap.computeIfAbsent(fuzzAction.getActionCmd(), FuzzActionResult::new);
        fuzzActionResult.addAction(fuzzAction);
        return true;
    }

    public boolean addActionResultByCmd(String actionCmd, long durationMillis) {
        FuzzActionResult fuzzActionResult = resultMap.computeIfAbsent(actionCmd, FuzzActionResult::new);
        fuzzActionResult.addAction(durationMillis);
        return true;
    }

    public String getResultsString() {
        String newLineStr = System.getProperty("line.separator");
        StringBuilder builder = new StringBuilder();
        for (FuzzActionResult fuzzActionResult : resultMap.values()) {
            builder.append(fuzzActionResult.getResultsString());
            builder.append(newLineStr);
        }

        return builder.toString();
    }
}
