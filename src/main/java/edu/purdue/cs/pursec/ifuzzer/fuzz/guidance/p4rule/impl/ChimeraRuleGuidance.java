package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.impl;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.api.FuzzP4RuleGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api.P4EntitiesMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.impl.P4EntitiesPacketAwareGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.impl.P4EntitiesRandomMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api.P4TableEntryMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl.P4TableEntryProgramAwareMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl.P4TableEntryRandomMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4CoverageReplyWithError;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;

public class ChimeraRuleGuidance extends FuzzP4RuleGuidance {

    P4EntitiesMutator[] entitiesMutators = {
            new P4EntitiesRandomMutator(),
            new P4EntitiesPacketAwareGenerator(),
    };

    P4TableEntryMutator[] tableEntryMutators = {
            new P4TableEntryRandomMutator(),
            new P4TableEntryProgramAwareMutator(),
    };


    public ChimeraRuleGuidance() {
        for (P4EntitiesMutator entitiesMutator : entitiesMutators) {
            // Add table-entry mutator for random-based entities mutator
            if (!entitiesMutator.isGenerator())
                entitiesMutator.addTableEntryMutator(tableEntryMutators);
        }
    }

    @Nonnull
    @Override
    public P4EntitiesMutator getP4EntitiesMutator() {
        return this.entitiesMutators[rand.nextInt(this.entitiesMutators.length)];
    }
}
