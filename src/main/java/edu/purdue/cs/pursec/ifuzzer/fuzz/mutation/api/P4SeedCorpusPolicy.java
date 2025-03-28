package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.api;

public enum P4SeedCorpusPolicy {
    SINGLE,                 // add seed in one corpus
    UNIQUE_RULE,            // add seed in unique rule corpus
    UNIQUE_PACKET,          // add seed in unique packet-type corpus
    UNIQUE_RULE_AND_PACKET, // add seed in unique rule x packet-type corpus
}
