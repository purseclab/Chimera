package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.api.P4TableEntryMutator;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.*;
import p4.v1.P4RuntimeFuzz.Action.Param;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.FieldMatch.FieldMatchTypeCase;
import p4.v1.P4RuntimeFuzz.TableAction.TypeCase;
import p4testgen.P4Testgen.P4NameReply;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Random;

public class P4TableEntryRandomMutator extends P4TableEntryMutator {
    private static Logger log = LoggerFactory.getLogger(P4TableEntryRandomMutator.class);

    @Override
    public Entity_Fuzz getRandomTableEntry(@Nullable Entity_Fuzz entity, @Nullable String tableName) {
        TableEntry tableEntry = null;
        TableEntry.Builder entryBuilder = TableEntry.newBuilder();
        if (entity != null && entity.getEntityCase().equals(EntityCase.TABLE_ENTRY)) {
            tableEntry = entity.getTableEntry();
            entryBuilder = TableEntry.newBuilder(tableEntry);
        }

        // Mutate table name
        if (tableName != null) {
            entryBuilder.setTableName(tableName);
        } if (tableEntry != null) {
            entryBuilder.setTableName(FuzzUtil.mutateString(entryBuilder.getTableName(), rand));
        } else {
            entryBuilder.setTableName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
        }

        // Mutate priority
        if (rand.nextBoolean())
            mutatePriority(entryBuilder);

        if (tableEntry == null) {
            mutateAction(entryBuilder);
            mutateMatch(entryBuilder);
        } else if (rand.nextBoolean()) {
            mutateAction(entryBuilder);
        } else {
            mutateMatch(entryBuilder);
        }

        return Entity_Fuzz.newBuilder()
                .setTableEntry(entryBuilder.build())
                .build();
    }

    @Override
    public FieldMatch addRandomMatch(String tableName) {FieldMatch match = null;

        // 1) Generate from pure Random Values
        if (ConfigConstants.CONFIG_P4_MUTATE_RULE_SYNTAX && rand.nextBoolean()) {
            byte [] randBytes = new byte[rand.nextInt(100) + 1];
            rand.nextBytes(randBytes);
            for (int i = 0; i < ConfigConstants.CONFIG_P4_MAX_FUZZ_RETRY_CNT; i++) {
                try {
                    match = FieldMatch.parseFrom(randBytes);
                    break;
                } catch (InvalidProtocolBufferException e) {
                    log.warn("addRandomMatch(): " + e.getMessage());
                    randBytes = FuzzUtil.mutateBytes(randBytes, 0, rand);
                }
            }
        }

        // 2) Fill out random fields
        if (match == null) {
            FieldMatch.Builder builder = FieldMatch.newBuilder();

            // mutate match_name (used by ONOS)
            // TODO: random FieldId
            builder.setFieldName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));

            // mutate match_type and corresponding value
            FieldMatchTypeCase selectedCase = selectedCases[rand.nextInt(selectedCases.length)];

            switch (selectedCase) {
                case EXACT:
                    builder.setExact(FuzzUtil.randomExact(null, 0, rand));
                    break;
                case LPM:
                    builder.setLpm(FuzzUtil.randomLpm(null, 0, rand));
                    break;
                case TERNARY:
                    builder.setTernary(FuzzUtil.randomTernary(null, 0, rand));
                    break;
                case RANGE:
                    builder.setRange(FuzzUtil.randomRange(null, 0, rand));
                    break;
                case OPTIONAL:
                    builder.setOptional(FuzzUtil.randomOptional(null, 0, rand));
                    break;
                default:
                    /* Unreachable.. */
                    break;
            }
            match = builder.build();
        }

        return match;
    }

    @Override
    public FieldMatch modifyRandomMatch(@Nonnull FieldMatch match, String tableName) {
        FieldMatch.Builder builder = FieldMatch.newBuilder(match);
        int mutantItem = rand.nextInt(3);

        // 1) Mutate random value
        if (mutantItem == 0) {
            switch (match.getFieldMatchTypeCase()) {
                case FIELDMATCHTYPE_NOT_SET:
                    /* TODO: change others */
                    log.warn("Unsupported: Match is not set");
                    // Fall through to generate random type
                    mutantItem = 1;
                    break;
                case EXACT:
                    builder.setExact(FuzzUtil.randomExact(match.getExact(), 0, rand));
                    break;
                case LPM:
                    builder.setLpm(FuzzUtil.randomLpm(match.getLpm(), 0, rand));
                    break;
                case TERNARY:
                    builder.setTernary(FuzzUtil.randomTernary(match.getTernary(), 0, rand));
                    break;
                case RANGE:
                    builder.setRange(FuzzUtil.randomRange(match.getRange(), 0, rand));
                    break;
                case OPTIONAL:
                    builder.setOptional(FuzzUtil.randomOptional(match.getOptional(), 0, rand));
                    break;
                default:
                    /* TODO */
                    log.warn("Unsupported {} match", match.getFieldMatchTypeCase());
                    break;
            }
        }

        // 2) Fill out random fields
        if (mutantItem == 1) {
            FieldMatchTypeCase selectedCase = null;
            for (int i = 0; i < selectedCases.length; i++) {
                if (selectedCases[i] == match.getFieldMatchTypeCase()) {
                    // Select random type except current
                    int incIdx = rand.nextInt(4) + 1;
                    selectedCase = selectedCases[(i + incIdx) % selectedCases.length];
                    break;
                }
            }

            if (selectedCase == null) {
                int newIdx = rand.nextInt(selectedCases.length);
                selectedCase = selectedCases[newIdx];
            }

            switch (selectedCase) {
                case EXACT:
                    builder.setExact(FuzzUtil.randomExact(null, 0, rand));
                    break;
                case LPM:
                    builder.setLpm(FuzzUtil.randomLpm(null, 0, rand));
                    break;
                case TERNARY:
                    builder.setTernary(FuzzUtil.randomTernary(null, 0, rand));
                    break;
                case RANGE:
                    builder.setRange(FuzzUtil.randomRange(null, 0, rand));
                    break;
                case OPTIONAL:
                    builder.setOptional(FuzzUtil.randomOptional(null, 0, rand));
                    break;
                default:
                    /* Unreachable.. */
                    break;
            }
        }

        // 3) Mutate field name
        if (mutantItem == 2) {
            String oldMatchName = match.getFieldName();
            if (!oldMatchName.isEmpty()) {
                builder.setFieldName(FuzzUtil.mutateString(oldMatchName, rand));
            } else {
                builder.setFieldName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
            }
        }

        return builder.build();
    }

    @Override
    public TableAction addRandomAction(String tableName) {
        TableAction.Builder builder = TableAction.newBuilder();

        // Action
        Action.Builder actionBuilder = Action.newBuilder();
        actionBuilder.setActionName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));

        // Action.param
        int mutateParamCnt = rand.nextInt(INIT_RANDOM_PARAM_LEN);
        for (int i = 0; i < mutateParamCnt; i++)
            mutateParam(actionBuilder);

        // Set action in builder
        if (rand.nextBoolean()) {
            // (1) ActionProfile
            builder.setActionProfileActionSet(ActionProfileActionSet.newBuilder()
                    .addActionProfileActions(ActionProfileAction.newBuilder()
                            .setAction(actionBuilder.build())
                            .build())
                    .build());
        } else {
            // (2) Action
            builder.setAction(actionBuilder.build());
        }

        return builder.build();
    }

    @Override
    public TableAction modifyRandomAction(@Nonnull TableAction action, String tableName) {
        TableAction.Builder builder = TableAction.newBuilder(action);

        // Find Action
        Action.Builder actionBuilder;
        if (action.getActionProfileActionSet().getActionProfileActionsCount() > 0) {
            // TODO: support multiple profile action
            actionBuilder = Action.newBuilder(action.getActionProfileActionSet()
                    .getActionProfileActions(0)
                    .getAction());
        } else if (action.getTypeCase().equals(TypeCase.ACTION)) {
            actionBuilder = Action.newBuilder(action.getAction());
        } else {
            return addRandomAction(tableName);
        }

        if (rand.nextBoolean()) {
            /* Keep action and mutate param */
            mutateParam(actionBuilder);

        } else {
            /* mutate action */
            String oldActionName = actionBuilder.getActionName();
            if (!oldActionName.isEmpty()) {
                actionBuilder.setActionName(FuzzUtil.mutateString(oldActionName, rand));
            } else {
                actionBuilder.setActionName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
            }
        }

        // Set action in builder
        if (rand.nextBoolean()) {
            // (1) ActionProfile
            builder.setActionProfileActionSet(ActionProfileActionSet.newBuilder()
                    .addActionProfileActions(ActionProfileAction.newBuilder()
                            .setAction(actionBuilder.build())
                            .build())
                    .build());
        } else {
            // (2) Action
            builder.setAction(actionBuilder.build());
        }

        return builder.build();
    }

    @Override
    public Action.Builder mutateParam(@Nonnull Action.Builder builder) {
        int opr = rand.nextInt(builder.getParamsCount() > 0 ? 3 : 1);
        int targetId;
        switch (opr) {
            case 0:
                builder.addParams(addRandomParam());
                break;
            case 1:
                targetId = rand.nextInt(builder.getParamsCount());
                builder.setParams(targetId, modifyRandomParam(builder.getParams(targetId),
                        builder.getActionName()));
                break;
            case 2:
                targetId = rand.nextInt(builder.getParamsCount());
                builder.removeParams(targetId);
                break;
        }

        return builder;
    }

    @Override
    public Param modifyRandomParam(@Nonnull Param param, String actionName) {
        Action.Param.Builder paramBuilder = Action.Param.newBuilder(param);
        if (rand.nextBoolean()) {
            // (1) mutate name
            String oldActionName = paramBuilder.getParamName();
            if (!oldActionName.isEmpty()) {
                paramBuilder.setParamName(FuzzUtil.mutateString(oldActionName, rand));
            } else {
                paramBuilder.setParamName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
            }
        } else {
            // (2) mutate value
            byte[] randBytes = FuzzUtil.mutateBytes(paramBuilder.getParamNameBytes().toByteArray(), 0, rand);
            paramBuilder.setValue(ByteString.copyFrom(randBytes));
        }
        return paramBuilder.build();
    }

    private Action.Param addRandomParam() {
        Action.Param.Builder paramBuilder = Action.Param.newBuilder();
        String paramName = FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand);
        paramBuilder.setParamName(paramName);
        int byteLen = rand.nextInt(FuzzUtil.P4_MAX_VALUE_BYTES);
        if (byteLen > 0) {
            byte[] randBytes = new byte[byteLen];
            rand.nextBytes(randBytes);
            paramBuilder.setValue(ByteString.copyFrom(randBytes));
        }
        return paramBuilder.build();
    }
}
