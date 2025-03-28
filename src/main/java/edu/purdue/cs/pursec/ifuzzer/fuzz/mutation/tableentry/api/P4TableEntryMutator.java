package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import p4.v1.P4RuntimeFuzz.*;
import p4.v1.P4RuntimeFuzz.FieldMatch.FieldMatchTypeCase;
import p4.v1.P4RuntimeFuzz.TableAction.TypeCase;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Random;

public abstract class P4TableEntryMutator {
    protected final Random rand = new Random();

    public static final int INIT_RANDOM_NAME_LEN = 10;
    public static final int INIT_RANDOM_PARAM_LEN = 3;

    protected static final FieldMatchTypeCase[] selectedCases = {
            FieldMatchTypeCase.EXACT,
            FieldMatchTypeCase.LPM,
            FieldMatchTypeCase.TERNARY,
            FieldMatchTypeCase.RANGE,
            FieldMatchTypeCase.OPTIONAL,
    };

    public abstract Entity_Fuzz getRandomTableEntry(@Nullable Entity_Fuzz entity, @Nullable String tableName);
    public abstract FieldMatch addRandomMatch(String tableName);
    public abstract FieldMatch modifyRandomMatch(@Nonnull FieldMatch match, String tableName);
    public abstract TableAction addRandomAction(String tableName);
    public abstract TableAction modifyRandomAction(@Nonnull TableAction action, String tableName);
    public abstract Action.Builder mutateParam(@Nonnull Action.Builder builder);
    public abstract Action.Param modifyRandomParam(@Nonnull Action.Param param, String actionName);

    public TableEntry.Builder mutateMatch(@Nonnull TableEntry.Builder builder) {
        int opr = rand.nextInt(builder.getMatchCount() > 0 ? 3 : 1);
        int targetId;
        switch (opr) {
            case 0:
                builder.addMatch(addRandomMatch(builder.getTableName()));
                break;
            case 1:
                targetId = rand.nextInt(builder.getMatchCount());
                FieldMatch mutantMatch = modifyRandomMatch(builder.getMatch(targetId), builder.getTableName());
                builder.setMatch(targetId, mutantMatch);
                break;
            case 2:
                targetId = rand.nextInt(builder.getMatchCount());
                builder.removeMatch(targetId);
                break;
        }

        return builder;
    }

    public TableEntry.Builder mutateAction(@Nonnull TableEntry.Builder builder) {
        if (rand.nextBoolean()) {
            // TODO: multiple actions
            if (!builder.hasAction() || builder.getAction().getTypeCase().equals(TypeCase.TYPE_NOT_SET)) {
                builder.setAction(addRandomAction(builder.getTableName()));
            } else {
                builder.setAction(modifyRandomAction(builder.getAction(), builder.getTableName()));
            }
        } else {
            // For default action
            builder.clearAction();
        }

        return builder;
    }

    public TableEntry.Builder mutatePriority(@Nonnull TableEntry.Builder builder) {
        if (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && rand.nextBoolean()) {
            builder.setPriority(rand.nextInt(FuzzUtil.ONOS_MAX_PRIORITY));
        } else {
            // (MIN_PRIORITY, MAX_PRIORITY)
            builder.setPriority(rand.nextInt(FuzzUtil.P4_MAX_PRIORITY - 2) + FuzzUtil.P4_MIN_PRIORITY + 1);
        }
        return builder;
    }

    public FieldMatchTypeCase getMatchTypeCase(String type, Random random) {
        FieldMatchTypeCase typeCase = P4Util.getMatchTypeCase(type);
        if (typeCase == null)
            return selectedCases[random.nextInt(selectedCases.length)];

        return typeCase;
    }
}
