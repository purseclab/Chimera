package edu.purdue.cs.pursec.ifuzzer.util;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;

public class RuntimeConfig {
    public boolean ttfMode = false;
    public boolean testGenMode = false;

    public int intentCheckIntervalMs = ConfigConstants.CONFIG_INTENT_CHECK_INTERVAL_MS;
    public int intentWaitTimeout = ConfigConstants.CONFIG_INTENT_WAIT_TIMEOUT;
    public int flowCheckIntervalMs = ConfigConstants.CONFIG_FLOW_CHECK_INTERVAL_MS;
    public int flowWaitTimeoutSec = ConfigConstants.CONFIG_FLOW_WAIT_TIMEOUT_SEC;
    public int p4PacketWaitMs = ConfigConstants.CONFIG_P4_PACKET_WAIT_MS;
    public int onosInterfaceWaitIntervalMs = ConfigConstants.CONFIG_ONOS_INTERFACE_WAIT_INTERVAL_MS;
    public int onosInterfaceWaitTimeoutMs = ConfigConstants.CONFIG_ONOS_INTERFACE_WAIT_TIMEOUT_MS;
    public boolean applyDiffP4Rules = ConfigConstants.CONFIG_APPLY_DIFF_P4_RULES;

    @Override
    protected RuntimeConfig clone() {
        try {
            return (RuntimeConfig) super.clone();
        } catch (CloneNotSupportedException e) {
            return new RuntimeConfig();
        }
    }
}
