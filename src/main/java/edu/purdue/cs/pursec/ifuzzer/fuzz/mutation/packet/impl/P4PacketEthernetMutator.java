package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketInPortAwareMutator;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EthType.EtherType;
import org.onlab.packet.Ethernet;

import java.nio.ByteBuffer;

public class P4PacketEthernetMutator extends P4PacketInPortAwareMutator {
    private static final int MAX_NUM_MUTATE_ETHERNET = 100;
    @Override
    public byte[] getRandomPacket(byte[] packetBytes) {
        // 1. Generate valid Ethernet/IP packets
        // Do not care MAC/IP/PORT addresses
        if (packetBytes.length < Ethernet.ETHERNET_HEADER_LENGTH) {
            return FuzzUtil.insertRandomBytes(packetBytes, rand, Ethernet.ETHERNET_HEADER_LENGTH);

        } else if (packetBytes.length == Ethernet.ETHERNET_HEADER_LENGTH) {
            return FuzzUtil.mutateBytes(packetBytes, 0, rand);
        }

        // 2. Generate random ethType
        byte[] newPacketBytes = packetBytes.clone();
        if (rand.nextBoolean()) {
            boolean favored = rand.nextBoolean();
            short randEthType = FuzzUtil.randomEthType(favored, rand);
            ByteBuffer bb = ByteBuffer.allocate(2);
            bb.putShort(randEthType);
            byte[] randEthTypeBytes = bb.array();
            newPacketBytes = packetBytes.clone();
            newPacketBytes[Ethernet.DATALAYER_ADDRESS_LENGTH * 2] = randEthTypeBytes[0];
            newPacketBytes[Ethernet.DATALAYER_ADDRESS_LENGTH * 2 + 1] = randEthTypeBytes[1];

            // If pure random, return it
            if (!favored)
                return newPacketBytes;
        }

        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.put(packetBytes[Ethernet.ETHERNET_HEADER_LENGTH - 2]);
        bb.put(packetBytes[Ethernet.ETHERNET_HEADER_LENGTH - 1]);
        short ethType = bb.getShort(0);

        // 3. If etherType is unknown, simply mutate bytes
        if (EtherType.lookup(ethType).equals(EtherType.UNKNOWN)) {
            return FuzzUtil.mutateBytes(newPacketBytes, Ethernet.ETHERNET_HEADER_LENGTH, rand);
        }

        if (EtherType.lookup(ethType).equals(EtherType.MPLS_MULTICAST) ||
                EtherType.lookup(ethType).equals(EtherType.MPLS_UNICAST)) {
            boolean favored = rand.nextBoolean();
            short randEthType = FuzzUtil.randomEthType(favored, rand);
            ByteBuffer bb2 = ByteBuffer.allocate(2);
            bb2.putShort(randEthType);
            byte[] randEthTypeBytes = bb2.array();
            newPacketBytes = packetBytes.clone();
            newPacketBytes[Ethernet.DATALAYER_ADDRESS_LENGTH * 2] = randEthTypeBytes[0];
            newPacketBytes[Ethernet.DATALAYER_ADDRESS_LENGTH * 2 + 1] = randEthTypeBytes[1];

            // If pure random, return it
            if (!favored)
                return newPacketBytes;
        }

        // 4. Generate random IPv4 Protocol
        if (EtherType.lookup(ethType).equals(EtherType.IPV4)) {
            boolean favored = rand.nextBoolean();
            short randIpProto = FuzzUtil.randomIpv4Proto(favored, rand);
            newPacketBytes[Ethernet.ETHERNET_HEADER_LENGTH + 9] = (byte) (randIpProto & 0xff);

            // If pure random, return it
            if (!favored)
                return newPacketBytes;
        }

        // 5. depend on deserializer
        for (int mutateCnt = 0; mutateCnt < MAX_NUM_MUTATE_ETHERNET; mutateCnt++) {
            try {
                newPacketBytes = FuzzUtil.mutateBytes(newPacketBytes, Ethernet.ETHERNET_HEADER_LENGTH, rand);
                Ethernet.deserializer().deserialize(newPacketBytes, 0, newPacketBytes.length);
                break;
            } catch (DeserializationException ignored) {
            } catch (Exception e) {
                return newPacketBytes;
            }
        }

        return newPacketBytes;
    }
}
