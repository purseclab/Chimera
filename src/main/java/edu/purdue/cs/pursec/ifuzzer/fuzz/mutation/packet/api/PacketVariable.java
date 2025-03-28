package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

public class PacketVariable {
    private byte[] bits;
    private byte[] maskBits;
    private int bitLength;
    private int pos = 0;

    public PacketVariable(byte[] bits, byte[] maskBits, int bitLength) {
        this.bits = bits;
        this.maskBits = maskBits;
        this.bitLength = bitLength;
    }

    public PacketVariable(byte[] bits, byte[] maskBits, int bitLength, int pos) {
        this(bits, maskBits, bitLength);
        this.pos = pos;
    }

    public byte[] getBits() {
        return bits;
    }

    public byte[] getMaskBits() {
        return maskBits;
    }

    public int getBitLength() {
        return bitLength;
    }

    public void overwrite(PacketVariable that) throws IllegalArgumentException {
        if (this.pos % 8 != 0 || that.pos % 8 != 0) {
            throw new IllegalArgumentException("pos should be 8-bit align.");
        }

        // check length
        int maxLen = Integer.max(this.pos + this.bitLength, that.pos + that.bitLength);
        int startPos = Integer.min(this.pos, that.pos);
        int bitLen = maxLen - startPos;

        // extend this
        if (bitLen > bits.length * 8) {
            byte[] newBytes = new byte[(bitLen + 7) / 8];
            System.arraycopy(this.bits, 0, newBytes, (this.pos - startPos) / 8, this.bits.length);
            this.bits = newBytes;

            byte[] newMaskBytes = new byte[(bitLen + 7) / 8];
            System.arraycopy(this.maskBits, 0, newMaskBytes, (this.pos - startPos) / 8, this.maskBits.length);
            this.maskBits = newMaskBytes;
        }

        this.pos = startPos;

        // overwrite that into this
        for (int i = this.pos; i < maxLen; i+=8) {
            if (i < that.pos)
                continue;
            else if (i >= that.pos + that.bitLength)
                break;

            int thisIdx = (i - this.pos) / 8;
            int thatIdx = (i - that.pos) / 8;
            int newByte = that.bits[thatIdx] & that.maskBits[thatIdx];
            int curByte = this.bits[thisIdx] & this.maskBits[thisIdx] & ~that.maskBits[thatIdx];
            this.maskBits[thisIdx] |= that.maskBits[thatIdx];
            this.bits[thisIdx] = (byte) (curByte | newByte);
        }

        // update
        bitLength = maxLen;
        pos = startPos;
    }
}
