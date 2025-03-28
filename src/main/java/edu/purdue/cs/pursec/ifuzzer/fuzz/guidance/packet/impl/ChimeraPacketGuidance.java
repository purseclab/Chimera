package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.FuzzP4PacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl.P4PacketEthernetMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl.P4PacketParserAwareGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl.P4PacketRandomMutator;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;

public class ChimeraPacketGuidance extends FuzzP4PacketGuidance {
    P4PacketMutator[] mutators = {
            new P4PacketRandomMutator(),
//            new P4PacketEthernetMutator(),
            new P4PacketParserAwareGenerator(),
    };

    @Nonnull
    @Override
    public P4PacketMutator getP4PacketMutator() {
        return mutators[rand.nextInt(mutators.length)];
    }
}
