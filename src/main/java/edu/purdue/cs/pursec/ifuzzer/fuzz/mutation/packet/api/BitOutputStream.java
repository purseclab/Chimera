package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class BitOutputStream {
    private ByteArrayOutputStream byteArrayOutputStream;
    private int currentByte;
    private int numBitsInCurrentByte;
    private int totalBits;

    public BitOutputStream() {
        this.byteArrayOutputStream = new ByteArrayOutputStream();
        this.totalBits = 0;
        this.currentByte = 0;
        this.numBitsInCurrentByte = 0;
    }

    public void write(byte[] bits, int bitLength) {
        this.write(bits, 0, bitLength);
    }

    public void write(byte[] bits, int startBit, int bitLength) {

        for (int i = startBit; i < bitLength; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);

            int bit = (bits[byteIndex] >> bitIndex) & 1;
            writeBit(bit);
        }

        totalBits += bitLength;
    }

    private void writeBit(int bit) {
        currentByte = (currentByte << 1) | bit;
        numBitsInCurrentByte++;

        if (numBitsInCurrentByte == 8) {
            byteArrayOutputStream.write(currentByte);
            currentByte = 0;
            numBitsInCurrentByte = 0;
        }
    }

    public void close() throws IOException {
        byteArrayOutputStream.close();
    }

    public int getTotalBits() {
        return totalBits;
    }

    public byte[] toByteArray() throws IOException {
        // Write any remaining bits in the last byte (padded with zeros)
        if (numBitsInCurrentByte > 0) {
            currentByte = currentByte << (8 - numBitsInCurrentByte);
            byteArrayOutputStream.write(currentByte);
        }
        return byteArrayOutputStream.toByteArray();
    }
}
