package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.ActionFuzzStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.FuzzP4PacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl.P4PacketRandomMutator;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.time.LocalDateTime;

public class FP4PacketGuidance extends RandomPacketGuidance {

    public FP4PacketGuidance() {
        this.mutator.disablePacketOut();
    }

    @Override
    public ActionFuzzStatus continueActionFuzzing() {
        if (startTime != null &&
                Duration.between(startTime, LocalDateTime.now()).compareTo(execDuration) >= 0) {
            return ActionFuzzStatus.DONE;
        }

        // FP4 run continuously
        return ActionFuzzStatus.PROCESSING;
    }
}
