package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;

public abstract class Coverage {
    public abstract boolean hasBitmap();
    public abstract void storeCoverageMap(String filePath);
    public abstract void storeCoverageTtf(PrintStream fw) throws IOException;
    public abstract boolean updateCoverage(@Nullable Coverage that);

    public void storeCoverageTtf(String filePath) {
        try (PrintStream fw = new PrintStream(filePath)) {
            storeCoverageTtf(fw);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
