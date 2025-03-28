package edu.purdue.cs.pursec.ifuzzer.util;

import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import io.grpc.ManagedChannel;
import p4testgen.P4FuzzGuideGrpc;
import p4testgen.P4Testgen.HealthCheckRequest;
import p4testgen.P4Testgen.HealthCheckResponse;

import java.util.concurrent.TimeUnit;

public class P4AgentDesc {
    public enum AgentStatus {
        INIT,
        ACTIVE,
        TERMINATING,
    }

    private AgentStatus agentStatus = AgentStatus.INIT;
    private final String agentAddr;
    private final int agentPid;

    public P4AgentDesc(String agentAddr, int agentPid) {
        this.agentAddr = agentAddr;
        this.agentPid = agentPid;
    }

    public P4AgentDesc(String agentAddr) {
        this(agentAddr, -1);
    }

    public void setAgentStatus(AgentStatus agentStatus) {
        this.agentStatus = agentStatus;
    }

    public int getAgentPid() {
        return agentPid;
    }

    public String getAgentAddr() {
        return agentAddr;
    }

    public AgentStatus getAgentStatus() {
        return agentStatus;
    }
}
