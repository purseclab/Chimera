package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import p4testgen.P4Testgen;

import java.util.Random;

public abstract class P4PacketMutator {
    protected final Random rand = new Random();
    protected boolean allowPacketOut = true;

    public abstract P4Testgen.TestCase getRandomP4Packet(P4Testgen.TestCase packetTest);
    public void disablePacketOut() {
        allowPacketOut = false;
    }
}
