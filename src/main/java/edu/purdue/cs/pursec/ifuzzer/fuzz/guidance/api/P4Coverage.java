package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import javax.annotation.Nullable;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.BitSet;

public class P4Coverage extends Coverage {
    private final BitSet traceBits;
    private int bitmapSize;
    private final String deviceId;

    public P4Coverage(String deviceId, byte[] traceBits, int bitmapSize) {
        this.deviceId = deviceId;
        this.bitmapSize = bitmapSize;
        this.traceBits = BitSet.valueOf(traceBits);
    }

    public P4Coverage(P4Coverage cov) {
        this.traceBits = (BitSet)cov.traceBits.clone();
        this.bitmapSize = cov.bitmapSize;
        this.deviceId = cov.deviceId;
    }

    @Override
    public boolean updateCoverage(@Nullable Coverage that) {
        if (!(that instanceof P4Coverage))
            return false;

        P4Coverage p4That = (P4Coverage)that;
        if (!this.deviceId.equals(p4That.deviceId))
            return false;

        BitSet prevTraceBits = (BitSet)this.traceBits.clone();
        this.traceBits.or(p4That.traceBits);
        this.bitmapSize = Integer.max(this.bitmapSize, p4That.bitmapSize);
        return (!prevTraceBits.equals(this.traceBits));
    }

    public String getDeviceId() {
        return deviceId;
    }

    public static String getStatsHeader() {
        return "P4Stmt(deviceId, hit, mapSize)";
    }

    public int getHitCount() {
        return traceBits.cardinality();
    }

    public int getMapSize() {
        return bitmapSize;
    }

    public String getStatsString(boolean printTime) {
        StringBuilder sb = new StringBuilder();
        if (printTime) {
            sb.append(System.currentTimeMillis());
            sb.append(", ");
        }
        //sb.append(deviceId);
        sb.append(this.getHitCount());
        sb.append(", ");
        sb.append(this.getMapSize());

        return sb.toString();
    }


    @Override
    public void storeCoverageMap(String filePath) {
        try (DataOutputStream fw = new DataOutputStream(Files.newOutputStream(Paths.get(filePath)))) {
            fw.writeInt(bitmapSize);
            fw.write(traceBits.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void storeCoverageTtf(PrintStream fw) {
        for (int i = 0; i < this.bitmapSize; i++) {
            if (this.traceBits.get(i))
                fw.printf("%d:1\n", i);
        }
    }

    @Override
    public boolean hasBitmap() {
        return true;
    }

    public static P4Coverage of(String filePath) {
        try (DataInputStream fr = new DataInputStream(Files.newInputStream(Paths.get(filePath)))) {
            int bitmapSize = fr.readInt();
            if (bitmapSize == 0)
                throw new IOException("Wrong bitmap size: 0");

            int byteLen = ((bitmapSize - 1) / 8) + 1;
            byte[] bytes = new byte[byteLen];
            fr.read(bytes, 0, byteLen);

            // NOTE: no deviceId
            return new P4Coverage(null, bytes, bitmapSize);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
