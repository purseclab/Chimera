package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api.P4TableEntryMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import p4testgen.P4Testgen;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

public abstract class P4EntitiesMutator {
    protected final Random rand = new Random();
    protected List<P4TableEntryMutator> tableEntryMutatorList = new ArrayList<>();

    public abstract P4Testgen.TestCase getRandomEntities(@Nonnull P4Testgen.TestCase ruleTest);
    public abstract boolean isGenerator();

    public P4TableEntryMutator getTableEntryMutator() {
        return tableEntryMutatorList.get(rand.nextInt(tableEntryMutatorList.size()));
    }

    public P4EntitiesMutator addTableEntryMutator(P4TableEntryMutator... tableEntryMutators) {
        this.tableEntryMutatorList.addAll(List.of(tableEntryMutators));
        return this;
    }
}
