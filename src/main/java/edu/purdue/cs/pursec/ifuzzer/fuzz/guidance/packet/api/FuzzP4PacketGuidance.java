package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.ActionFuzzStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.FuzzP4Guidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.SkipFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketMutator;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4CoverageReplyWithError;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.time.LocalDateTime;

public abstract class FuzzP4PacketGuidance extends FuzzP4Guidance {
    public int fuzzActionCnt;
    public LocalDateTime startTime = null;
    public Duration execDuration = null;

    public abstract @Nonnull P4PacketMutator getP4PacketMutator();

    public void init() {
        startTime = null;
        execDuration = null;
    }

    public TestCase getRandomP4Packet(TestCase packetTest) throws EndFuzzException, SkipFuzzException {
        P4CoverageReplyWithError covReply;

        P4PacketMutator packetMutator = getP4PacketMutator();

        for (int i = 0; i < ConfigConstants.CONFIG_P4_MAX_FUZZ_RETRY_CNT; i++) {
            /* fuzz from getRandomAction() directly or init p4test action */
            TestCase newPacketTest = packetMutator.getRandomP4Packet(packetTest);
            covReply = p4UtilInstance.recordP4Testgen(
                    ConfigConstants.CONFIG_P4_TESTED_DEVICE_ID, newPacketTest);

            // If error occurs, continue mutation or throw exception
            if (isInvalidTestCase(newPacketTest, covReply))
                continue;

            /* set valid packet based on new entities */
            newPacketTest = covReply.getResp().getTestCase();

            if (isInvalidOutputPort(newPacketTest))
                continue;

            if (isInvalidTestCase(newPacketTest, covReply))
                continue;

            return newPacketTest;
        }

        throw new SkipFuzzException();
    }


    public void initFuzzActionCnt(int fuzzActionCnt, LocalDateTime startTime, Duration execDuration) {
        this.fuzzActionCnt = fuzzActionCnt;
        this.startTime = startTime;
        this.execDuration = execDuration;
    }

    public void setFuzzActionCnt(int fuzzActionCnt) {
        this.fuzzActionCnt = fuzzActionCnt;
    }

    public ActionFuzzStatus continueActionFuzzing() {
        if (startTime != null &&
                Duration.between(startTime, LocalDateTime.now()).compareTo(execDuration) >= 0) {
            return ActionFuzzStatus.DONE;
        }

        // If count is negative value, run continuously
        if (fuzzActionCnt < 0)
            return ActionFuzzStatus.PROCESSING;

        if (fuzzActionCnt-- > 0)
            return ActionFuzzStatus.PROCESSING;

        return ActionFuzzStatus.DONE;
    }

    public boolean isContinuous() {
        return (ConfigConstants.CONFIG_P4_FUZZ_PACKET_CNT > 0);
    }

}
