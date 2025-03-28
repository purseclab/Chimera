package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

public class SkipFuzzException extends Exception {
    public SkipFuzzException() {
    }

    public SkipFuzzException(String message) {
        super(message);
    }
}
