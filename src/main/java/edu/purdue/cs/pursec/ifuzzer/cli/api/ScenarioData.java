package edu.purdue.cs.pursec.ifuzzer.cli.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.scenarioGuidance;

public class ScenarioData {
    private final FuzzScenario scenario;
    private final File scenarioFile;

    public ScenarioData(File scenarioFile) {
        this.scenario = null;
        this.scenarioFile = scenarioFile;
    }

    public ScenarioData(FuzzScenario scenario) {
        this.scenario = scenario;
        this.scenarioFile = null;
    }

    public @Nonnull FuzzScenario getFuzzScenario(boolean genLoadHost) throws IOException {
        if (this.scenario != null)
            return this.scenario;

        assert(this.scenarioFile != null);

        JsonObject scenarioJson = TestUtil.fromJson(new FileReader(this.scenarioFile));
        if (scenarioJson == null)
            throw new IOException("No JsonObject");

        FuzzScenario scenario = new FuzzScenario(scenarioJson, genLoadHost);
        scenario.setReplayFile(scenarioFile);
        return scenario;
    }

    public JsonObject getFuzzScenarioJson() throws IOException {
        if (this.scenario != null)
            return this.scenario.toJsonObject();

        assert(this.scenarioFile != null);
        return TestUtil.fromJson(new FileReader(this.scenarioFile));
    }

    public String getFileName() {
        if (this.scenarioFile == null)
            return null;

        return this.scenarioFile.getName();
    }

    public File getFile() {
        return scenarioFile;
    }
}
