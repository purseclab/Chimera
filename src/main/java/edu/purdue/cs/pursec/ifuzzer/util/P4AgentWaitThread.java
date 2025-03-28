package edu.purdue.cs.pursec.ifuzzer.util;

import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import io.grpc.ManagedChannel;
import p4testgen.P4FuzzGuideGrpc;
import p4testgen.P4Testgen.HealthCheckRequest;
import p4testgen.P4Testgen.HealthCheckResponse;

import java.util.concurrent.TimeUnit;

public class P4AgentWaitThread extends Thread {
    private final P4AgentDesc desc;

    public P4AgentWaitThread(P4AgentDesc desc) {
        this.desc = desc;
    }

    @Override
    public void run() {
        // Check status
        while (true) {
            ManagedChannel channel = Grpc.newChannelBuilder(desc.getAgentAddr(),
                            InsecureChannelCredentials.create()).build();
            P4FuzzGuideGrpc.P4FuzzGuideBlockingStub blockingStub = P4FuzzGuideGrpc.newBlockingStub(channel);

            try {
                HealthCheckResponse resp = blockingStub
                        .withDeadlineAfter(P4Util.CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS,
                                TimeUnit.MILLISECONDS)
                        .hello(HealthCheckRequest.newBuilder().build());

                if (resp != null && resp.getStatus() > 0)
                    return;

            } catch (Exception ignore) {
            } finally {
                try {
                    channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignore) {}
            }

            try {
                Thread.sleep(P4Util.CONFIG_P4TOOL_HELLO_WAIT_TIMEOUT_MS);
            } catch (InterruptedException ignore) {}
        }
    }
}
