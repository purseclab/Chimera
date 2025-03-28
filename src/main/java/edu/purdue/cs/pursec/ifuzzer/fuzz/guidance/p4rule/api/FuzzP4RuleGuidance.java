package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.p4rule.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.FuzzP4Guidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.entities.api.P4EntitiesMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4CoverageReplyWithError;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.util.List;

public abstract class FuzzP4RuleGuidance extends FuzzP4Guidance {

    public abstract @Nonnull P4EntitiesMutator getP4EntitiesMutator();

    public TestCase getRandomP4Entities(@Nonnull TestCase ruleTest) throws EndFuzzException, SkipFuzzException {
        P4CoverageReplyWithError covReply;

        P4EntitiesMutator entitiesMutator = getP4EntitiesMutator();

        for (int i = 0; i < ConfigConstants.CONFIG_P4_MAX_FUZZ_RETRY_CNT; i++) {
            /* fuzz from getRandomAction() directly or init p4test action */
            TestCase newRuleTest = entitiesMutator.getRandomEntities(ruleTest);
            if (entitiesMutator.isGenerator()) {
                covReply = p4UtilInstance.genRuleP4Testgen(
                        ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, newRuleTest);
            } else {
                covReply = p4UtilInstance.recordP4Testgen(
                        ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, newRuleTest);
            }

            // If error occurs, continue mutation or throw exception
            if (isInvalidTestCase(newRuleTest, covReply))
                continue;

            /* set valid packet based on new entities */
            newRuleTest = covReply.getResp().getTestCase();

            if (isInvalidOutputPort(newRuleTest))
                continue;

            if (entitiesMutator.isGenerator()) {
                // Remove invalid ones!
                List<Entity_Fuzz> newEntities = P4Util.getEntities(newRuleTest.getEntitiesList(), true);
                newRuleTest = TestCase.newBuilder(newRuleTest)
                        .clearEntities()
                        .addAllEntities(newEntities)
                        .build();
            }

            return newRuleTest;
        }

        throw new SkipFuzzException();
    }
}
