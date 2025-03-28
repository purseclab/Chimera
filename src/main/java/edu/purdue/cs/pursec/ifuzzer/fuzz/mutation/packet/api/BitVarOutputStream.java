package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import java.io.IOException;

class ValidBitsMetadata {
    int startBit;
    int bitLen;

    public ValidBitsMetadata(int startBit, int bitLen) {
        this.startBit = startBit;
        this.bitLen = bitLen;
    }
}

public class BitVarOutputStream {
    BitOutputStream valueBitStream;
    BitOutputStream maskBitStream;

    public BitVarOutputStream() {
        valueBitStream = new BitOutputStream();
        maskBitStream = new BitOutputStream();
    }

    public void write(BitVariable bitVariable) {
        valueBitStream.write(bitVariable.getBytes(), bitVariable.getBitLength());
        maskBitStream.write(bitVariable.getMaskBits(), bitVariable.getBitLength());
    }

    public PacketVariable toPacketVar() throws IOException {

        return new PacketVariable(valueBitStream.toByteArray(), maskBitStream.toByteArray(),
                valueBitStream.getTotalBits());
    }

    public PacketVariable toPacketVar(int pos) throws IOException {

        return new PacketVariable(valueBitStream.toByteArray(), maskBitStream.toByteArray(),
                valueBitStream.getTotalBits(), pos);
    }

    public void close() throws IOException {
        valueBitStream.close();
        maskBitStream.close();
    }
}

