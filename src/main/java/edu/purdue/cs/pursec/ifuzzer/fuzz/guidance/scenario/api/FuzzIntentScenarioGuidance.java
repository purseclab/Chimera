package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.scenario.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.result.IntentScenarioFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;

import javax.annotation.Nonnull;
import java.io.IOException;

public abstract class FuzzIntentScenarioGuidance extends FuzzScenarioGuidance {

    // stats
    private IntentScenarioFuzzResult fuzzResult;

    /** concrete methods **/
    public void init(Object o, String resultDirPath) throws IOException, InterruptedException {
        super.init(o, resultDirPath);
        fuzzResult = new IntentScenarioFuzzResult();
    }

    @Override
    public boolean addActionResult(FuzzAction fuzzAction) {
        /* result will be added on later */
        return false;
    }

    @Override
    public boolean addActionResultByCmd(String actionCmd, long durationMillis) {
        return false;
    }

    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        return fuzzResult.addScenarioResult(fuzzScenario);
    }

    public String getResultsString() {
        return fuzzResult.getResultsString();
    }
}
