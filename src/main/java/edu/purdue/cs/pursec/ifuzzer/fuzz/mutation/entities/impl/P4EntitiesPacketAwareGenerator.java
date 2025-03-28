package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api.P4TableEntryMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api.P4EntitiesMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl.P4TableEntryProgramAwareMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.TableEntry;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.P4NameReply;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class P4EntitiesPacketAwareGenerator extends P4EntitiesMutator {
    private static Logger log = LoggerFactory.getLogger(P4EntitiesPacketAwareGenerator.class);
    private static final P4Util p4UtilInstance = P4Util.getInstance();
    private final P4TableEntryProgramAwareMutator tableEntryMutator = new P4TableEntryProgramAwareMutator();

    @Override
    public P4TableEntryMutator getTableEntryMutator() {
        return tableEntryMutator;
    }

    @Override
    public boolean isGenerator() {
        return true;
    }

    /**
     * getRandomEntities: PacketAwareGenerator will do three steps:
     *      1) Remove invalid rules
     *      2) Generate uncovered tables
     *      3) Mutate an action among valid rules that have the highest
     *          priority for each table.
     * @param ruleTest: given test
     * @return updated ruleTest
     */
    @Override
    public TestCase getRandomEntities(@Nonnull TestCase ruleTest) {
        P4Testgen.TestCase.Builder ruleBuilder = P4Testgen.TestCase.newBuilder(ruleTest);

        // 1) Get valid & mutant entities.
        // We skip default entities even though they can have the highest priority.
        List<Entity_Fuzz> validMutantEntities = P4Util.getEntities(ruleBuilder.getEntitiesList(),
                true, true);
        List<Entity_Fuzz> defaultEntities = P4Util.getEntities(ruleBuilder.getEntitiesList(),
                true, false);

        ruleBuilder.clearEntities();
        Set<String> validTableNameSet = new HashSet<>();
        if (!validMutantEntities.isEmpty()) {
            validTableNameSet = validMutantEntities.stream()
                    .map(v -> v.getTableEntry().getTableName())
                    .collect(Collectors.toSet());

            // 2) Collect highest mutant rules for each table
            Map<String, Integer> highestEntityIndexMap = new HashMap<>();
            for (int i = 0; i < validMutantEntities.size(); i++) {
                Entity_Fuzz entity = validMutantEntities.get(i);
                TableEntry tableEntry = entity.getTableEntry();
                String tableName = tableEntry.getTableName();

                if (highestEntityIndexMap.containsKey(tableName)) {
                    int oldIdx = highestEntityIndexMap.get(tableName);
                    Entity_Fuzz oldEntity = validMutantEntities.get(oldIdx);
                    if (oldEntity.getTableEntry().getPriority() < tableEntry.getPriority())
                        highestEntityIndexMap.put(tableName, i);
                } else {
                    highestEntityIndexMap.put(tableName, i);
                }
            }

            // 3) Mutate action
            List<Integer> highestEntities = new ArrayList<>(highestEntityIndexMap.values());
            int targetIdx = highestEntities.get(rand.nextInt(highestEntities.size()));
            Entity_Fuzz targetEntity = validMutantEntities.get(targetIdx);

            assert (targetEntity.getEntityCase().equals(EntityCase.TABLE_ENTRY));

            Entity_Fuzz.Builder entityBuilder = Entity_Fuzz.newBuilder(targetEntity);
            TableEntry targetEntry = targetEntity.getTableEntry();
            TableEntry.Builder entryBuilder = TableEntry.newBuilder(targetEntry);

            // Clear match and mutate action
            entryBuilder.clearMatch();
            entryBuilder.setAction(getTableEntryMutator().modifyRandomAction(
                    entryBuilder.getAction(),
                    entryBuilder.getTableName()));

            // 4) Replace existing to all valid rules
            // update valid entity
            validMutantEntities.set(targetIdx, entityBuilder
                    .setTableEntry(entryBuilder.build())
                    .setIsDefaultEntry(0)
                    .build());
            ruleBuilder.addAllEntities(validMutantEntities);

            log.debug("GEN/1 ADD {} valid entry(s)", validMutantEntities.size());
        }

        ruleBuilder.addAllEntities(defaultEntities);
        log.debug("GEN/2 ADD {} default entry(s)", defaultEntities.size());

        // 5) Generate rules for uncovered entities
        // Find all possible tables first.
        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_TABLE, null);
        if (rep != null && rep.getNameCount() > 0) {
            List<String> uncoveredTableList;
            if (validTableNameSet.isEmpty()) {
                uncoveredTableList = rep.getNameList();

            } else {
                uncoveredTableList = new ArrayList<>();
                for (String tableName : rep.getNameList()) {
                    if (!validTableNameSet.contains(tableName))
                        uncoveredTableList.add(tableName);
                }
            }

            // XXX: Add all table rules all at once!
            for (String uncoveredTableName : uncoveredTableList) {
                TableEntry.Builder entryBuilder = TableEntry.newBuilder();
                entryBuilder.setTableName(uncoveredTableName);
                entryBuilder.setPriority(100);
//                entryBuilder.addMatch(getTableEntryMutator().addRandomMatch(uncoveredTableName));
                entryBuilder.setAction(getTableEntryMutator().addRandomAction(uncoveredTableName));
                ruleBuilder.addEntities(Entity_Fuzz.newBuilder()
                        .setTableEntry(entryBuilder.build())
                        .build());
            }
            log.debug("GEN/3 ADD {} uncovered entry(s)", uncoveredTableList.size());
        }

        return ruleBuilder.build();
    }
}
