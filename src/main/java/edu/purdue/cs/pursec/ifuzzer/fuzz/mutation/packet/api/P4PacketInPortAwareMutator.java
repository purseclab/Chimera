package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api;

import com.google.protobuf.ByteString;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.InputPacketAtPort;
import p4testgen.P4Testgen.TestCase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public abstract class P4PacketInPortAwareMutator extends P4PacketMutator {
    private static Logger log = LoggerFactory.getLogger(P4PacketInPortAwareMutator.class);

    public abstract byte[] getRandomPacket(byte[] packetBytes);

    @Override
    public TestCase getRandomP4Packet(TestCase packetTest) {
        P4Testgen.TestCase.Builder testBuilder = P4Testgen.TestCase.newBuilder(packetTest);

        InputPacketAtPort.Builder packetBuilder = InputPacketAtPort.newBuilder(packetTest.getInputPacket());
        byte[] packetBytes = packetBuilder.getPacket().toByteArray();
        int packetOutByteLen = 0;

        if (rand.nextBoolean()) {
            // mutate input port
            packetBuilder.setPort(FuzzUtil.generateP4ValidPort(rand, allowPacketOut));
        }

        if (packetBuilder.getPort() == ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
            packetOutByteLen = FuzzUtil.getPacketOutLen();
        }

        // Randomly generate packet
        byte[] prefixBytes = null, newPacketBytes;
        if (packetOutByteLen == 0 || packetBytes.length <= packetOutByteLen || rand.nextBoolean()) {
            // (1) Mutate bytes including PKTOUT header
            newPacketBytes = getRandomPacket(packetBytes);

            // In case of packet outs, app agent will generate specific headers automatically
            // (basic/int.p4: 2B header / fabric.p4: ethtype as 0xbf01)
            if (packetOutByteLen == 2 || packetOutByteLen == 14) {
                // Must put packetOut header to reduce unnecessary packets denied by app-agent
                int outPortNo = FuzzUtil.generateP4ValidPort(rand, true);
                prefixBytes = FuzzUtil.generatePacketOut(outPortNo, packetOutByteLen, rand);
            }

        } else {
            // (2) Mutate bytes excluding PKTOUT header
            prefixBytes = Arrays.copyOfRange(packetBytes, 0, packetOutByteLen);
            if (rand.nextBoolean()) {
                int outPortNo = FuzzUtil.generateP4ValidPort(rand, true);
                prefixBytes = FuzzUtil.generatePacketOut(outPortNo, packetOutByteLen, rand);
            }
            newPacketBytes = getRandomPacket(Arrays.copyOfRange(packetBytes, packetOutByteLen, packetBytes.length));
        }

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        // write prefix if it exists
        if (prefixBytes != null) {
            try {
                byteStream.write(prefixBytes);
            } catch (IOException e) {
                log.error("writing pktout metadata: " + e.getMessage());
            }
        }

        // write mutant packet
        try {
            byteStream.write(newPacketBytes);
        } catch (IOException e) {
            log.error("writing packet: " + e.getMessage());
        }

        if (byteStream.size() > 0) {
            packetBuilder.setPacket(ByteString.copyFrom(byteStream.toByteArray()));
        } else {
            log.error("mutant packet size is 0");
            packetBuilder.setPacket(ByteString.copyFrom(new byte[] {(byte)rand.nextInt(0x100)}));
        }

        return testBuilder.setInputPacket(packetBuilder.build())
                .build();
    }
}
