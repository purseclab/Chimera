package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.api.FuzzP4RuleGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api.P4EntitiesMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.impl.P4EntitiesRandomMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api.P4TableEntryMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl.P4TableEntryRandomMutator;

import javax.annotation.Nonnull;

public class RandomRuleGuidance  extends FuzzP4RuleGuidance {

    P4EntitiesMutator entitiesMutator = new P4EntitiesRandomMutator();
    P4TableEntryMutator tableEntryMutators = new P4TableEntryRandomMutator();


    public RandomRuleGuidance() {
        entitiesMutator.addTableEntryMutator(tableEntryMutators);
    }

    @Nonnull
    @Override
    public P4EntitiesMutator getP4EntitiesMutator() {
        return this.entitiesMutator;
    }
}
