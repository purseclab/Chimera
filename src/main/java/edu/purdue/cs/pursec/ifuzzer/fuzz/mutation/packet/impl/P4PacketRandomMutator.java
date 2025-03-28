package edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.impl;

import edu.purdue.cs.pursec.ifuzzer.fuzz.mutation.packet.api.P4PacketInPortAwareMutator;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class P4PacketRandomMutator extends P4PacketInPortAwareMutator {
    private static Logger log = LoggerFactory.getLogger(P4PacketRandomMutator.class);
    private final static int PACKET_MAX_LEN = 1200;
    private final static int MUTATE_BYTE_WINDOW_LEN = 20;

    private enum PACKET_MUTATOR_TYPE {
        INSERT_BYTE(0, PACKET_MAX_LEN),
        DELETE_BYTE(1, Integer.MAX_VALUE),
        MODIFY_BYTE(1, Integer.MAX_VALUE),
        FLIP_BYTE(1, Integer.MAX_VALUE),
        DUPLICATE_SEG(1, PACKET_MAX_LEN),
        SWAP_SEG(2, Integer.MAX_VALUE),
        TRUNCATE(1, Integer.MAX_VALUE),
        EXPAND(0, PACKET_MAX_LEN);

        private final int minLen;
        private final int maxLen;

        PACKET_MUTATOR_TYPE(int minLen, int maxLen) {
            this.minLen = minLen;
            this.maxLen = maxLen;
        }

        public static List<PACKET_MUTATOR_TYPE> getValidTypes(byte[] packetBytes) {
            List<PACKET_MUTATOR_TYPE> validTypes = new ArrayList<>();
            for (PACKET_MUTATOR_TYPE type : values()) {
                if (packetBytes.length >= type.minLen &&
                        packetBytes.length < type.maxLen) {
                    validTypes.add(type);
                }
            }
            return validTypes;
        }
    }

    @Override
    public byte[] getRandomPacket(byte[] packetBytes) {
        List<PACKET_MUTATOR_TYPE> validTypes = PACKET_MUTATOR_TYPE.getValidTypes(packetBytes);
        if (validTypes.size() == 0) {
            log.error("No valid operators for seed packet");
            return packetBytes;
        }

        byte[] newBytes;
        PACKET_MUTATOR_TYPE type = validTypes.get(rand.nextInt(validTypes.size()));
        switch (type) {
            case INSERT_BYTE:
                newBytes = FuzzUtil.insertRandomByte(packetBytes, 0, rand);
                break;
            case DELETE_BYTE:
                newBytes = FuzzUtil.modifyRandomByte(packetBytes, 0, rand);
                break;
            case MODIFY_BYTE:
                newBytes = FuzzUtil.deleteRandomByte(packetBytes, 0, rand);
                break;
            case FLIP_BYTE:
                newBytes = FuzzUtil.flipRandomByte(packetBytes, 0, rand);
                break;
            case DUPLICATE_SEG:
                newBytes = FuzzUtil.dupSegment(packetBytes, PACKET_MAX_LEN, MUTATE_BYTE_WINDOW_LEN, rand);
                break;
            case SWAP_SEG:
                newBytes = FuzzUtil.swapSegment(packetBytes, MUTATE_BYTE_WINDOW_LEN, rand);
                break;
            case TRUNCATE:
                newBytes = FuzzUtil.truncateBytes(packetBytes, rand);
                break;
            case EXPAND:
                newBytes = FuzzUtil.expandBytes(packetBytes, PACKET_MAX_LEN, MUTATE_BYTE_WINDOW_LEN, rand);
                break;
            default:
                /* Unreachable... */
                newBytes = packetBytes;
                break;
        }

        return newBytes;
    }
}
