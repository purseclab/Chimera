package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import java.io.IOException;

public abstract class P4TypeStruct {
    public abstract void decode(BitVarOutputStream bitStream) throws IOException;

    public PacketVariable toPacket() throws IOException {
        BitVarOutputStream bitStream = new BitVarOutputStream();
        decode(bitStream);
        return bitStream.toPacketVar();
    }
}
