package edu.purdue.cs.pursec.ifuzzer.store.impl;

import edu.purdue.cs.pursec.ifuzzer.store.api.GeneralStore;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;

import java.util.List;

public class RuleStore extends GeneralStore<List<Entity_Fuzz>> {

    /**
     * Singleton
     */
    private static class InnerRuleStore {
        private static final RuleStore instance;

        static {
            try {
                instance = new RuleStore();
            } catch (Exception e) {
                e.printStackTrace();
                throw new ExceptionInInitializerError(e);
            }
        }
    }

    public static RuleStore getInstance() {
        return RuleStore.InnerRuleStore.instance;
    }
}
