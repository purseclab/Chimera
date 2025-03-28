package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class BitVariable {
    private byte[] bits;
    private byte[] maskBits;
    private int bitLength;
    private int childPos;
    private Map<Integer, BitVariable> sliceBits = new TreeMap<>();

    // Constructor to initialize bit array with given length in bits
    public BitVariable(int bitLength) {
        if (bitLength <= 0) {
            throw new IllegalArgumentException("Bit length must be positive");
        }
        this.bitLength = bitLength;
        this.bits = new byte[(bitLength + 7) / 8]; // calculate required bytes
        this.maskBits = new byte[(bitLength + 7) / 8];
    }

    public BitVariable(int bitLength, long value) {
        this(bitLength);
        this.putValue(value);
    }

    public BitVariable slice(int endBit, int startBit) throws IllegalArgumentException {
        if (childPos > 0)
            throw new IllegalArgumentException("Unsupported tree of bit slices");

        if (endBit >= bitLength)
            throw new IllegalArgumentException(String.format("Slice [%d:%d] is out-of-bound (len: %d)",
                    endBit, startBit, bitLength));

        int childBitLen = endBit - startBit + 1;
        BitVariable childBits;
        if (sliceBits.containsKey(startBit)) {
            childBits = sliceBits.get(startBit);
            if (childBits.bitLength != childBitLen) {
                throw new IllegalArgumentException("Unsupported duplicate range of bit slice");
            }
        } else {
            childBits = new BitVariable(childBitLen);
            childBits.childPos = startBit;
            sliceBits.put(startBit, childBits);
        }
        return childBits;
    }

    // Constructor to initialize bit array from a boolean value
    public void putBool(boolean value) {
        assert(sliceBits.isEmpty());
        if (value) {
            bits[0] = (byte) 0x80; // Set MSB if true
            maskBits[0] = (byte) 0x80;
        }
    }

    // Constructor to initialize bit array from an int value with given length in bits
    public void putInt(int value) {
        assert(sliceBits.isEmpty());
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(value);
        byte[] intBytes = buffer.array();
        System.arraycopy(intBytes, 4 - this.bits.length, this.bits, 0, this.bits.length);
        fillMaskBits();
    }

    // Constructor to initialize bit array from a long value with given length in bits
    public void putValue(long value) {
        assert(sliceBits.isEmpty());
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(value);
        byte[] longBytes = buffer.array();
        System.arraycopy(longBytes, 8 - this.bits.length, this.bits, 0, this.bits.length);
        fillMaskBits();
    }

    public void putValue(long value, long mask) {
        assert(sliceBits.isEmpty());
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(value);
        byte[] longBytes = buffer.array();
        System.arraycopy(longBytes, 8 - this.bits.length, this.bits, 0, this.bits.length);

        buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(mask);
        byte[] longMaskBytes = buffer.array();
        System.arraycopy(longMaskBytes, 8 - this.maskBits.length, this.maskBits, 0, this.maskBits.length);
    }

    public void putRandom() {
        Random rand = new Random();
        assert(sliceBits.isEmpty());
        rand.nextBytes(bits);
        int remainingBits = bitLength % 8;
        if (remainingBits != 0) {
            // Zero out the bits in the last byte that are beyond the bit length
            int mask = 0xFF << (8 - remainingBits);
            bits[bits.length - 1] &= mask;
        }
        fillMaskBits();
    }

    // Method to convert bits to an int value
    public int toInt() {
        if (bitLength > 32) {
            throw new IllegalStateException("Bit length exceeds 32 bits, cannot convert to int");
        }

        // TODO: the length of bits can be higher than 4
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        buffer.put(new byte[4 - this.bits.length]); // pad with zeros if needed
        buffer.put(this.bits);

        buffer.rewind();
        int tmpInt = buffer.getInt();
        int maskInt = (int)((1L << bitLength) - 1);
        return tmpInt & maskInt;
    }

    // Method to convert bits to a long value
    public long toLong() {
        if (bitLength > 64) {
            throw new IllegalStateException("Bit length exceeds 64 bits, cannot convert to long");
        }

        // TODO: the length of bits can be higher than 8
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buffer.put(new byte[8 - bits.length]); // pad with zeros if needed
        buffer.put(bits);

        buffer.rewind();
        long tmpLong = buffer.getLong();
        long maskLong = bitLength == 64 ? -1L : (1L << bitLength) - 1;
        return tmpLong & maskLong;
    }

    // Method to get the bit array as a string for debugging
    public String toBitString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bitLength; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            sb.append((bits[byteIndex] >> bitIndex) & 1);
        }
        return sb.toString();
    }

    // Method to get the byte array
    public byte[] getBytes() {
        return bits;
    }

    public byte[] getMaskBits() {
        return maskBits;
    }

    public boolean isAllocated() {
        for (byte maskBit : maskBits)
            if (maskBit != 0)
                return true;
        return false;
    }

    public int getBitLength() {
        return bitLength;
    }

    public void decode(BitVarOutputStream bitStream) throws IOException {
        mergeChildBits();
        bitStream.write(this);
    }

    private void mergeChildBits() throws IOException {
        BitOutputStream bitStream = new BitOutputStream();
        int curPos = 0;
        for (BitVariable slice : sliceBits.values()) {
            if (curPos < slice.childPos) {
                bitStream.write(this.bits, curPos, slice.childPos - curPos);
            }
            bitStream.write(slice.getBytes(), 0, slice.bitLength);
            curPos = slice.childPos + slice.bitLength;
        }
        if (curPos < bitLength)
            bitStream.write(this.bits, curPos, bitLength - curPos);

        this.bits = bitStream.toByteArray();


        BitOutputStream maskBitStream = new BitOutputStream();
        curPos = 0;
        for (BitVariable slice : sliceBits.values()) {
            if (curPos < slice.childPos) {
                maskBitStream.write(this.maskBits, curPos, slice.childPos - curPos);
            }
            maskBitStream.write(slice.getMaskBits(), 0, slice.bitLength);
            curPos = slice.childPos + slice.bitLength;
        }
        if (curPos < bitLength)
            maskBitStream.write(this.maskBits, curPos, bitLength - curPos);

        this.maskBits = maskBitStream.toByteArray();

        sliceBits.clear();
    }

    private void fillMaskBits() {
        Arrays.fill(maskBits, (byte) 0xFF);
        int remainingBits = bitLength % 8;
        if (remainingBits != 0) {
            // Zero out the bits in the last byte that are beyond the bit length
            int mask = 0xFF << (8 - remainingBits);
            maskBits[maskBits.length - 1] &= mask;
        }
    }
}
