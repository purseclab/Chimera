package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.impl;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api.P4EntitiesMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.TableEntry;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class P4EntitiesRandomMutator extends P4EntitiesMutator {
    private static Logger log = LoggerFactory.getLogger(P4EntitiesRandomMutator.class);

    private Queue<TestCase> testCaseToMergeQ;

    public P4EntitiesRandomMutator() {
        testCaseToMergeQ = new LinkedList<>();
    }

    @Override
    public boolean isGenerator() {
        return false;
    }

    @Override
    public TestCase getRandomEntities(@Nonnull TestCase ruleTest) {
        P4Testgen.TestCase.Builder ruleBuilder = P4Testgen.TestCase.newBuilder(ruleTest);

        /* Optimize: Check the number of valid rules */
        Map<Integer, Entity_Fuzz> entitiesMap = IntStream.range(0, ruleTest.getEntitiesCount())
                .boxed()
                .collect(Collectors.toMap(i -> i, ruleTest::getEntities));

        List<Integer> validRuleIndices = entitiesMap.entrySet().stream()
                .filter(e -> e.getValue().getEntityCase().equals(EntityCase.TABLE_ENTRY))
                .filter(e -> (e.getValue().getTableEntry().getIsValidEntry() & 1) > 0)  // 1) valid rules
                .map(Entry::getKey)
                .collect(Collectors.toList());

        List<Integer> mutantRuleIndices = entitiesMap.entrySet().stream()
                .filter(e -> e.getValue().getEntityCase().equals(EntityCase.TABLE_ENTRY))
                .filter(e -> (e.getValue().getTableEntry().getIsValidEntry() & 1) > 0)  // 1) valid rules
                .filter(e -> (e.getValue().getIsDefaultEntry() & 1) == 0) // 2) except default entries
                .map(Entry::getKey)
                .collect(Collectors.toList());

        // Store ruleTest randomly
        if (ConfigConstants.CONFIG_MAX_NUM_STORE_CASE_TO_MERGE > 0 &&
                !testCaseToMergeQ.contains(ruleTest) &&
                ruleTest.getEntitiesCount() < ConfigConstants.CONFIG_SOFT_LIMIT_ENTITIES_CNT / 2 &&
                rand.nextInt(ConfigConstants.CONFIG_PERIOD_STORE_CASE_TO_MERGE) == 0) {
            if (testCaseToMergeQ.size() > ConfigConstants.CONFIG_MAX_NUM_STORE_CASE_TO_MERGE)
                testCaseToMergeQ.poll();
            testCaseToMergeQ.add(ruleTest);
        }

        int opr;
        if (ruleTest.getEntitiesCount() > ConfigConstants.CONFIG_SOFT_LIMIT_ENTITIES_CNT)
            opr = rand.nextInt(2) + 1;  /* MODIFY or DELETE */
        else if (testCaseToMergeQ.isEmpty())
            opr = rand.nextInt(mutantRuleIndices.size() > 0 ? 5 : 1);   /* w/o MERGE */
        else
            opr = rand.nextInt(mutantRuleIndices.size() > 0 ? 6 : 1);   /* w/  MERGE */

        int targetId;
        List<Entity_Fuzz> entityList;
        TableEntry targetEntry;
        // Operators: add, modify, delete, copy, add same table rules, merge
        switch (opr) {
            case 0:
                /* ADD */
                log.debug("ADD 1 entry + {}", ruleTest.getEntitiesCount());
                ruleBuilder.addEntities(getTableEntryMutator().getRandomTableEntry(null, null));
                break;

            case 1:
                /* MODIFY */
                log.debug("MODIFY 1 entry on {}", ruleTest.getEntitiesCount());
                entityList = ruleTest.getEntitiesList();
                targetId = mutantRuleIndices.remove(rand.nextInt(mutantRuleIndices.size()));
                ruleBuilder.setEntities(targetId, getTableEntryMutator()
                        .getRandomTableEntry(entityList.get(targetId), null));
                break;

            case 2:
                /* DELETE */
                log.debug("DELETE 1 entry - {}", ruleTest.getEntitiesCount());
                targetId = mutantRuleIndices.remove(rand.nextInt(mutantRuleIndices.size()));
                ruleBuilder.removeEntities(targetId);
                break;

            case 3:
                /* COPY */
                log.debug("COPY 1 entry + {}", ruleTest.getEntitiesCount());
                entityList = ruleTest.getEntitiesList();
                targetId = validRuleIndices.get(rand.nextInt(validRuleIndices.size()));
                TableEntry tableEntry = TableEntry.newBuilder(entityList.get(targetId).getTableEntry())
                        .build();
                ruleBuilder.addEntities(Entity_Fuzz.newBuilder()
                        .setTableEntry(tableEntry)
                        .setIsDefaultEntry(0)
                        .build());
                break;

            case 4:
                /* ADD SAME TABLE RULE */
                log.debug("ADD-RULE 1 entry + {}", ruleTest.getEntitiesCount());
                entityList = ruleTest.getEntitiesList();
                targetId = mutantRuleIndices.get(rand.nextInt(mutantRuleIndices.size()));
                targetEntry = entityList.get(targetId).getTableEntry();

                ruleBuilder.setEntities(targetId, getTableEntryMutator()
                        .getRandomTableEntry(null, targetEntry.getTableName()));
                break;

            case 5:
                /* MERGE */
                TestCase testCaseToMerge = testCaseToMergeQ.poll();
                if (testCaseToMerge != null && testCaseToMerge.getEntitiesCount() > 0) {
                    List<Entity_Fuzz> mergeList = P4Util.getEntities(testCaseToMerge.getEntitiesList(), true, true);
                    log.debug("MERGE {} entry(s) + {}", mergeList.size(),
                            ruleTest.getEntitiesCount());
                    ruleBuilder.addAllEntities(mergeList);
                }
                break;
        }

        return ruleBuilder.build();
    }
}
