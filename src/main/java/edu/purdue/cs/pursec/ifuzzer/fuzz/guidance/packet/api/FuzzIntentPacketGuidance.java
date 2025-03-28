package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;

import java.util.List;

public interface FuzzIntentPacketGuidance {
    void init();
    void addTestIntent(TestIntent intent);
    void removeTestIntent(TestIntent intent);
    List<TestIntent> getTestIntents();
    JsonObject getValidTestJson(ReachabilityIntent intent);
    JsonObject getRandomPacketJson() throws EndFuzzException;
    boolean isContinuous();
}
