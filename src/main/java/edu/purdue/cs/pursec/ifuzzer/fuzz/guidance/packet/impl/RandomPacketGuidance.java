package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.FuzzP4PacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl.P4PacketRandomMutator;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;

public class RandomPacketGuidance extends FuzzP4PacketGuidance {
    P4PacketMutator mutator = new P4PacketRandomMutator();

    @Nonnull
    @Override
    public P4PacketMutator getP4PacketMutator() {
        return mutator;
    }
}
