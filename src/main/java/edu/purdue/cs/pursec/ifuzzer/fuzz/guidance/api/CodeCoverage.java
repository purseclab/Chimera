package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;

import javax.annotation.Nullable;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;

public class CodeCoverage extends Coverage {
    protected byte[] traceBits = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
    private int mapSize = ConfigConstants.COVERAGE_MAP_SIZE;
    private int cachedHitCount = -1;

    public static byte numberOfLeadingZeros(byte i) {
        // HD, Count leading 0's
        if (i <= 0)
            return (byte) (i == 0 ? 8 : 0);
        byte n = 7;
        if (i >= 1 <<  4) { n -=  4; i >>>=  4; }
        if (i >= 1 <<  2) { n -=  2; i >>>=  2; }
        return (byte) (n - (i >>> 1));
    }

    /* Returns the highest order bit */
    public static byte hobFromByte(byte num) {
        return (byte) (num & (Byte.MIN_VALUE >>> numberOfLeadingZeros(num)));
    }

    public static byte hobFromInt(int num) {
        // (24) 1000 0000 (8)
        if (Integer.numberOfLeadingZeros(num) >= 24)
            return Byte.MIN_VALUE;
        return hobFromByte((byte)num);
    }

    public CodeCoverage() {}

    public CodeCoverage(byte[] traceBits) {
        this.traceBits = traceBits.clone();
        this.mapSize = traceBits.length;
    }

    public CodeCoverage deepCopy() {
        return new CodeCoverage(this.traceBits);
    }

    public void initTraceBits(int mapSize) {
        this.traceBits = new byte[mapSize];
        this.mapSize = mapSize;
        this.cachedHitCount = -1;
    }

    public int getHitCount() {
        if (cachedHitCount >= 0)
            return cachedHitCount;

        int hitCount = 0;
        for (int i = 1; i < this.mapSize; i++) {
            if (this.traceBits[i] != 0)
                hitCount ++;
        }
        cachedHitCount = hitCount;

        return hitCount;
    }

    public byte[] getTraceBits() {
        return traceBits;
    }

    public int getMapSize() {
        return mapSize;
    }

    public void putBitmap(ByteBuffer buf) {
        buf.put(traceBits);
    }

    @Override
    public boolean updateCoverage(@Nullable Coverage that) {

        if (!(that instanceof CodeCoverage))
            return false;

        CodeCoverage codeThat = (CodeCoverage)that;
        boolean changed = false;
        assert(this.mapSize == codeThat.mapSize);

        this.traceBits[0] = 1;
        for (int i = 1; i < this.mapSize; i++) {
            int before = this.traceBits[i];
            this.traceBits[i] |= hobFromByte(codeThat.traceBits[i]);

            if (!changed && before != this.traceBits[i]) {
                changed = true;
            }
        }

        if (changed)
            cachedHitCount = -1;

        return changed;
    }

    public void diffCoverage(CodeCoverage that) {
        boolean changed = false;

        assert(this.mapSize == that.mapSize);

        this.traceBits[0] = 1;
        for (int i = 1; i < this.mapSize; i++) {
            // Do nothing
            if (this.traceBits[i] == 0)
                continue;

            if (that.traceBits[i] != 0) {
                this.traceBits[i] |= that.traceBits[i];
            } else {
                // Mask out
                this.traceBits[i] = 0;
            }
        }
    }

    public Collection<?> computeNewCoverage(CodeCoverage baseline) {
        Collection<Integer> newCoverage = new ArrayList<>();
        for (int i = 1; i < this.mapSize; i++) {
            if (this.traceBits[i] != 0 && baseline.traceBits[i] == 0)
                newCoverage.add(i);
        }

        return newCoverage;
    }

    @Override
    public void storeCoverageMap(String filePath) {
        try (OutputStream fw = Files.newOutputStream(Paths.get(filePath))) {
            fw.write(this.traceBits, 0, this.mapSize);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void storeCoverageTtf(PrintStream fw) throws IOException {
        for (int i = 0; i < this.mapSize; i++) {
            if (this.traceBits[i] != 0)
                fw.printf("%d:%d\n", i, Byte.toUnsignedInt(this.traceBits[i]));
        }
    }

    @Override
    public boolean hasBitmap() {
        return true;
    }

    public static CodeCoverage of(String filePath) {
        try (InputStream fr = Files.newInputStream(Paths.get(filePath))) {
            byte[] bytes = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
            fr.read(bytes, 0, ConfigConstants.COVERAGE_MAP_SIZE);

            return new CodeCoverage(bytes);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
