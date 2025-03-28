package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.tableentry.impl;

import com.google.protobuf.ByteString;
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
import java.util.Arrays;
import java.util.Random;

public class P4TableEntryProgramAwareMutator extends P4TableEntryMutator {
    protected static final P4Util p4UtilInstance = P4Util.getInstance();
    private static Logger log = LoggerFactory.getLogger(P4TableEntryProgramAwareMutator.class);
    @Override
    public Entity_Fuzz getRandomTableEntry(@Nullable Entity_Fuzz entity, @Nullable String tableName) {
        TableEntry tableEntry = null;
        TableEntry.Builder entryBuilder = TableEntry.newBuilder();
        if (entity != null && entity.getEntityCase().equals(EntityCase.TABLE_ENTRY)) {
            tableEntry = entity.getTableEntry();
            entryBuilder = TableEntry.newBuilder(tableEntry);
        }

        // Fill out random fields
        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_TABLE, null);

        // Mutate table name
        if (tableName != null) {
            entryBuilder.setTableName(tableName);
        } else if (rep != null && rep.getNameCount() > 0) {
            // Choose one of table names
            entryBuilder.setTableName(rep.getName(rand.nextInt(rep.getNameCount())));
        } else if (tableEntry != null) {
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
    public FieldMatch addRandomMatch(String tableName) {
        FieldMatch.Builder builder = FieldMatch.newBuilder();

        // mutate match_name (used by ONOS)
        // TODO: random FieldId
        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_MATCH, tableName);
        int idx = -1;
        if (rep != null && rep.getNameCount() > 0) {
            idx = rand.nextInt(rep.getNameCount());
            builder.setFieldName(rep.getName(idx));
        } else {
            builder.setFieldName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
        }

        // mutate match_type and corresponding value
        FieldMatchTypeCase selectedCase;
        if (idx >= 0) {
            selectedCase = getMatchTypeCase(rep.getType(idx), rand);
        } else {
            selectedCase = selectedCases[rand.nextInt(selectedCases.length)];
        }

        int bitLen = 0;
        if (idx >= 0) {
            bitLen = rep.getBitLen(idx);
        }

        switch (selectedCase) {
            case EXACT:
                builder.setExact(FuzzUtil.randomExact(null, bitLen, rand));
                break;
            case LPM:
                builder.setLpm(FuzzUtil.randomLpm(null, bitLen, rand));
                break;
            case TERNARY:
                builder.setTernary(FuzzUtil.randomTernary(null, bitLen, rand));
                break;
            case RANGE:
                builder.setRange(FuzzUtil.randomRange(null, bitLen, rand));
                break;
            case OPTIONAL:
                builder.setOptional(FuzzUtil.randomOptional(null, bitLen, rand));
                break;
            default:
                /* Unreachable.. */
                break;
        }
        return builder.build();
    }

    @Override
    public FieldMatch modifyRandomMatch(@Nonnull FieldMatch match, String tableName) {
        FieldMatch.Builder builder = FieldMatch.newBuilder(match);

        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_MATCH, tableName);
        int idx = -1;
        if (rep != null && rep.getNameCount() > 0) {
            if (rand.nextBoolean()) {
                /* mutate match and generate field */
                idx = rand.nextInt(rep.getNameCount());
                builder.setFieldName(rep.getName(idx));
            } else {
                /* keep match and mutate field */
                for (int i = 0; i < rep.getNameCount(); i++) {
                    String matchName = rep.getName(i);
                    if (matchName.equals(match.getFieldName())) {
                        idx = i;
                        break;
                    }
                }
            }
        }

        // Mutate random value
        int bitLen = 0;
        if (idx >= 0)
            bitLen = rep.getBitLen(idx);

        switch (match.getFieldMatchTypeCase()) {
            case FIELDMATCHTYPE_NOT_SET:
                /* TODO: change others */
                log.warn("Unsupported: Match is not set");
                break;
            case EXACT:
                builder.setExact(FuzzUtil.randomExact(match.getExact(), bitLen, rand));
                break;
            case LPM:
                builder.setLpm(FuzzUtil.randomLpm(match.getLpm(), bitLen, rand));
                break;
            case TERNARY:
                builder.setTernary(FuzzUtil.randomTernary(match.getTernary(), bitLen, rand));
                break;
            case RANGE:
                builder.setRange(FuzzUtil.randomRange(match.getRange(), bitLen, rand));
                break;
            case OPTIONAL:
                builder.setOptional(FuzzUtil.randomOptional(match.getOptional(), bitLen, rand));
                break;
            default:
                /* TODO */
                log.warn("Unsupported {} match", match.getFieldMatchTypeCase());
                break;
        }

        return builder.build();
    }

    @Override
    public TableAction addRandomAction(String tableName) {
        TableAction.Builder builder = TableAction.newBuilder();

        // Find Action
        Action.Builder actionBuilder = Action.newBuilder();

        // TODO: random ActionId
        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_ACTION, tableName);
        int idx = -1;
        if (rep != null && rep.getNameCount() > 0) {
            idx = rand.nextInt(rep.getNameCount());
            actionBuilder.setActionName(rep.getName(idx));
        } else {
            actionBuilder.setActionName(FuzzUtil.getRandomChars(rand.nextInt(INIT_RANDOM_NAME_LEN), rand));
        }

        String newActionName = actionBuilder.getActionName();
        P4NameReply paramRep = p4UtilInstance.getP4Name(P4Util.P4_NAME_PARAM, newActionName);
        // Has parameter
        if (paramRep != null && paramRep.getNameCount() > 0) {
            for (int i = 0; i < paramRep.getNameCount(); i++) {
                // generate correct param
                actionBuilder.addParams(addRandomParam(paramRep.getName(i),
                        FuzzUtil.bitLenToByteLen(paramRep.getBitLen(i))));
            }
        }

        // Check whether action requires profile (in bitlen)
        boolean hasActionProfile = rand.nextBoolean();
        if (idx >= 0)
            hasActionProfile = (rep.getBitLen(idx) > 0);

        // Set action in builder
        if (hasActionProfile) {
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

        String newActionName = actionBuilder.getActionName();
        P4NameReply rep = p4UtilInstance.getP4Name(P4Util.P4_NAME_ACTION, tableName);

        int idx = -1;
        if (rep != null && rep.getNameCount() > 0 && rand.nextBoolean()) {
            /* mutate action and generate param */
            idx = rand.nextInt(rep.getNameCount());
            newActionName = rep.getName(idx);
            actionBuilder.setActionName(newActionName);

            P4NameReply paramRep = p4UtilInstance.getP4Name(P4Util.P4_NAME_PARAM, newActionName);
            actionBuilder.clearParams();
            // Has parameter
            if (paramRep != null && paramRep.getNameCount() > 0) {
                for (int i = 0; i < paramRep.getNameCount(); i++) {
                    // generate correct param
                    actionBuilder.addParams(addRandomParam(paramRep.getName(i),
                            FuzzUtil.bitLenToByteLen(paramRep.getBitLen(i))));
                }
            }

        } else {
            /* Keep action and mutate param */
            if (rep != null) {
                for (int i = 0; i < rep.getNameCount(); i++) {
                    String actionName = rep.getName(i);
                    if (actionName.equals(newActionName)) {
                        idx = i;
                        break;
                    }
                }
            }
            mutateParam(actionBuilder);
        }

        boolean hasActionProfile = false;
        if (idx >= 0)
            hasActionProfile = (rep.getBitLen(idx) > 0);

        // Set action in builder
        if (hasActionProfile) {
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
        if (builder.getParamsCount() == 0)
            return builder;

        int targetId = rand.nextInt(builder.getParamsCount());
        builder.setParams(targetId, modifyRandomParam(builder.getParams(targetId),
                builder.getActionName()));

        return builder;
    }

    @Override
    public Param modifyRandomParam(@Nonnull Param param, String actionName) {
        P4NameReply paramRep = p4UtilInstance.getP4Name(P4Util.P4_NAME_PARAM, actionName);

        if (paramRep == null || paramRep.getNameCount() == 0)
            return param;

        int paramByteLen = Integer.MAX_VALUE;
        for (int i = 0; i < paramRep.getNameCount(); i++) {
            String paramName = paramRep.getName(i);
            if (paramName.equals(param.getParamName())) {
                paramByteLen = FuzzUtil.bitLenToByteLen(paramRep.getBitLen(i));
                break;
            }
        }

        Action.Param.Builder paramBuilder = Action.Param.newBuilder(param);
        // mutate value
        byte[] curBytes = paramBuilder.getParamNameBytes().toByteArray();
        if (curBytes.length > paramByteLen)
            curBytes = Arrays.copyOf(curBytes, paramByteLen);

        byte[] randBytes = FuzzUtil.mutateBytes(curBytes, 0, rand);
        paramBuilder.setValue(ByteString.copyFrom(randBytes));

        return paramBuilder.build();
    }

    private Action.Param addRandomParam(String paramName, int byteLen) {
        Action.Param.Builder paramBuilder = Action.Param.newBuilder();
        paramBuilder.setParamName(paramName);
        if (byteLen > 0) {
            byte[] randBytes = new byte[byteLen];
            rand.nextBytes(randBytes);
            paramBuilder.setValue(ByteString.copyFrom(randBytes));
        }
        return paramBuilder.build();
    }
}
