package edu.purdue.cs.pursec.ifuzzer.util;

public enum ChimeraTTF {
    NO_BUG(0),
    BMV2_BUG1 (1),
    BMV2_BUG_EXPAND_HEADER(2),
    ONOS_BUG_CONTROLLER_HOST(3),
    ONOS_BUG_GROUP_DEL(4),
    ONOS_BUG_RULE_CHECK_DELAY(5),
    ONOS_BUG_DIRECT_ACTION(6),
    ONOS_BUG_PACKET_IN_DROP(7),
    ONOS_BUG_DEFAULT_ACTION(8),
    BMV2_BUG_SHRINK_HEADER(9),
    BMV2_BUG_EXPAND_HEADER_BY_CONTROLLER(10),
    BMV2_BUG_SHRINK_HEADER_BY_CONTROLLER(11);

    private final int bug_ttf_idx;

    ChimeraTTF(int bug_ttf_idx) {
        this.bug_ttf_idx = bug_ttf_idx;
    }

    public static ChimeraTTF fromIdx(int bug_ttf_idx) {
        for (ChimeraTTF ttf : values()) {
            if (ttf.bug_ttf_idx == bug_ttf_idx)
                return ttf;
        }
        return null;
    }

    public int getIdx() {
        return bug_ttf_idx;
    }
}
