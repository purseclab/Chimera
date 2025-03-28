package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl;

import com.google.protobuf.ByteString;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketMutator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.AutogenP4PktGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.PacketVariable;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.InputPacketAtPort;
import p4testgen.P4Testgen.TestCase;

import java.io.IOException;
import java.util.Optional;

public class P4PacketParserAwareGenerator extends P4PacketMutator {
    private static Logger log = LoggerFactory.getLogger(P4PacketParserAwareGenerator.class);
    private static AutogenP4PktGenerator generator = AutogenP4PktGenerator.get(ConfigConstants.CONFIG_P4_PIPELINE);

    @Override
    public TestCase getRandomP4Packet(TestCase packetTest) {


        P4Testgen.TestCase.Builder testBuilder = P4Testgen.TestCase.newBuilder(packetTest);

        InputPacketAtPort.Builder packetBuilder = InputPacketAtPort.newBuilder(packetTest.getInputPacket());
        byte[] packetBytes = packetBuilder.getPacket().toByteArray();

        // (2) Generate packet
        try {
            PacketVariable packetVar = generator.parser_impl(packetTest);
            Optional<Integer> inPort = generator.getInputPort();
            inPort.ifPresent(packetBuilder::setPort);
            byte[] newBytes = FuzzUtil.updateBytes(packetBytes, packetVar.getBits(),
                    packetVar.getMaskBits());
            // Optimize PKTOUT to invalid ports
            if (packetBuilder.getPort() == ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
                FuzzUtil.fillPacketOut(newBytes, FuzzUtil.generateP4ValidPort(rand, true),
                        FuzzUtil.getPacketOutLen());
            }
            packetBuilder.setPacket(ByteString.copyFrom(newBytes));

        } catch (IOException e) {
            log.error(e.getMessage());
        }

        return testBuilder.setInputPacket(packetBuilder.build())
                .build();
    }
}

