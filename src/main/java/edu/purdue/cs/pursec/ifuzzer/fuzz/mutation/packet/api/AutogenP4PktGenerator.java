package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.autogen.*;
import p4testgen.P4Testgen;

import java.io.IOException;
import java.util.Optional;

public abstract class AutogenP4PktGenerator {
    public abstract PacketVariable parser_impl(P4Testgen.TestCase testCase) throws IOException;

    public Optional<Integer> getInputPort() {
        return Optional.empty();
    }

    public static AutogenP4PktGenerator get(String pipeconfId) {
        if (pipeconfId.equals("org.onosproject.pipelines.basic")) {
            return new BasicPktGenerator();
        } else if (pipeconfId.equals("org.onosproject.pipelines.int")) {
            return new IntPktGenerator();
        } else if (pipeconfId.equals("org.stratumproject.fabric.bmv2")) {
            return new FabricPktGenerator();
        } else if (pipeconfId.equals("org.stratumproject.fabric-int.bmv2")) {
            return new FabricIntPktGenerator();
        } else if (pipeconfId.equals("org.stratumproject.fabric-upf.bmv2")) {
            return new FabricUpfPktGenerator();
        } else if (pipeconfId.equals("org.stratumproject.fabric-upf-int.bmv2")) {
            return new FabricUpfIntPktGenerator();
        } else {
            throw new IllegalArgumentException("Unknown pipeconf: " + pipeconfId);
        }
    }
}
