package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzScenario;

import java.io.IOException;
import java.util.UUID;

public class SeedScenario {
    private UUID uuid;
    private FuzzScenario scenario;

    public SeedScenario(FuzzScenario scenario) {
        this.scenario = scenario;
        this.uuid = UUID.randomUUID();
    }

    public UUID getUuid() {
        return uuid;
    }

    public FuzzScenario getScenario() {
        return scenario;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof SeedScenario))
            return false;

        SeedScenario that = (SeedScenario)obj;
        return this.scenario.equals(that.scenario);
    }
}
