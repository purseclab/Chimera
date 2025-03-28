package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

import java.util.Random;

public class AllZeroRandom extends Random {
    @Override
    protected int next(int bits) {
        return 0;
    }
}
