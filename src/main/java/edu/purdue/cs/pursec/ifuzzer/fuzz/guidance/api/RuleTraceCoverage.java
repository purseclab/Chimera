package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz.EntityCase;
import p4.v1.P4RuntimeFuzz.TableEntry;

import javax.annotation.Nullable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.stream.Collectors;

public class RuleTraceCoverage extends Coverage {
    private final String ruleKey;
    private final List<Entity_Fuzz> rules;
    private BitSet traceBits;
    private int bitmapSize;
    private final String deviceId;

    public RuleTraceCoverage(String deviceId, List<Entity_Fuzz> entityList) {
        this.deviceId = deviceId;
        this.traceBits = new BitSet();

        // get valid entries first.
        this.rules = new ArrayList<>();
        int i = 0;
        for (Entity_Fuzz entity : entityList) {
            if (!entity.getEntityCase().equals(EntityCase.TABLE_ENTRY))
                continue;
            TableEntry entry = entity.getTableEntry();
            if ((entry.getIsValidEntry() & 1) == 0)
                continue;

            // Add validEntry
            rules.add(entity);
            if (entity.getTableEntry().getMatchedIdx() >= 0)
                this.traceBits.flip(i);
            i++;
        }

        this.bitmapSize = rules.size();
        ruleKey = P4Util.genHashCode(rules);
    }

    public RuleTraceCoverage(RuleTraceCoverage cov) {
        this.deviceId = cov.deviceId;
        this.traceBits = (BitSet)cov.traceBits.clone();
        this.bitmapSize = cov.bitmapSize;
        this.ruleKey = cov.ruleKey;
        this.rules = new ArrayList<>(cov.rules);
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getRuleKey() {
        return ruleKey;
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
        sb.append(deviceId);
        sb.append(", ");
        sb.append(this.getHitCount());
        sb.append(", ");
        sb.append(this.getMapSize());

        return sb.toString();
    }

    @Override
    public void storeCoverageMap(String filePath) {
        try (DataOutputStream fw = new DataOutputStream(Files.newOutputStream(Paths.get(filePath)))) {
            fw.writeInt(this.bitmapSize);
            fw.write(this.traceBits.toByteArray());
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
    public boolean updateCoverage(@Nullable Coverage that) {
        if (!(that instanceof RuleTraceCoverage))
            return false;

        RuleTraceCoverage covThat = (RuleTraceCoverage)that;
        if (!this.deviceId.equals(covThat.deviceId))
            return false;

        if (!this.ruleKey.equals(covThat.ruleKey))
            return false;

        if (this.bitmapSize != covThat.bitmapSize)
            return false;

        BitSet prevTraceBits = (BitSet)this.traceBits.clone();
        this.traceBits.or(covThat.traceBits);
        return (!prevTraceBits.equals(this.traceBits));
    }

    @Override
    public boolean hasBitmap() {
        return false;
    }
}
