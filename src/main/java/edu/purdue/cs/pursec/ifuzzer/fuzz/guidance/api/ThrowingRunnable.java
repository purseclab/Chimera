package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

@FunctionalInterface
public interface ThrowingRunnable {
    void run() throws Exception;
}
