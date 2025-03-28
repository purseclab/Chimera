package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.protobuf.TextFormat;
import com.google.protobuf.TextFormat.ParseException;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import org.apache.commons.io.FileUtils;
import org.apache.commons.net.util.Base64;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class FuzzActionP4TestContent extends FuzzActionContent {
//    private String ruleProtobufStr = null;
    private static Logger log = LoggerFactory.getLogger(FuzzActionP4TestContent.class);
    private P4Testgen.TestCase testCase = null;

    public FuzzActionP4TestContent(JsonObject content) throws JsonParseException {
        super(content);

        // Get intent
        if (content.has("ruleFilePath")) {
            // Read file
            String ruleFilePath = content.get("ruleFilePath").getAsString();
            try {
                String protobufStr = new String(Files.readAllBytes(
                        Paths.get(IFuzzer.rootPath + File.separator + ruleFilePath)));
                testCase = P4Util.getTestfromProto(protobufStr);
            } catch (IOException e) {
                throw new JsonParseException("error while reading ruleFilePath: " + e.getMessage());
            }
        } else if (content.has("P4TestgenStr")) {
            try {
                String protobufStr = content.get("P4TestgenStr").getAsString();
                testCase = P4Util.getTestfromProto(protobufStr);

            } catch (IOException e) {
                throw new JsonParseException("error while parsing P4TestgenStr: " + e.getMessage());
            }
        } else if (content.has("P4Testgen")) {
            try {
                String protobufBase64 = content.get("P4Testgen").getAsString();
                testCase = TestCase.parseFrom(Base64.decodeBase64(protobufBase64));

            } catch (IOException e) {
                throw new JsonParseException("error while parsing P4Testgen: " + e.getMessage());
            }
        }
    }

    public FuzzActionP4TestContent(JsonObject content, P4Testgen.TestCase testCase) {
        super(content);
        this.testCase = testCase;
    }

    public void setTestCase(P4Testgen.TestCase newTestCase) {
        this.testCase = newTestCase;
    }

    public P4Testgen.TestCase getTestCase() {
        return this.testCase;
    }

    private boolean isAllMasked(P4Testgen.OutputPacketAtPort outputPacketAtPort) {
        byte[] maskBytes = outputPacketAtPort.getPacketMask().toByteArray();
        for (byte maskByte : maskBytes) {
            if (maskByte != (byte)0xff)
                return false;
        }
        return true;
    }

    public P4Testgen.TestCase getVerifyTest() throws ParseException {
        return testCase;
    }

    public P4Testgen.InputPacketAtPort getInputPacket() throws ParseException {
        // Send only entities.
        if (this.testCase == null)
            return null;

        return testCase.getInputPacket();
    }

    public List<P4Testgen.OutputPacketAtPort> getOutputPacket() throws ParseException {
        // Send only entities.
        if (this.testCase == null)
            return null;

        return testCase.getExpectedOutputPacketList();
    }

    @Override
    public FuzzActionP4TestContent deepCopy() {
        return new FuzzActionP4TestContent(this.content.deepCopy(), this.testCase);
    }
    @Override
    public String toString() {
        return super.toString() + ", " + this.testCase.toString();
    }

    @Override
    public JsonObject toJsonObject(boolean isLogging) throws IOException {
        JsonObject jsonObject = super.toJsonObject(isLogging);
        if (this.testCase != null) {
            if (isLogging) {
                toJsonObjectWithFile(jsonObject, this.testCase);

            } else {
                jsonObject.addProperty("P4Testgen",
                        Base64.encodeBase64String(this.testCase.toByteArray()));
                jsonObject.remove("P4TestgenStr");
                jsonObject.remove("ruleFilePath");
            }
        }

        return jsonObject;
    }

    private JsonObject toJsonObjectWithFile(JsonObject jsonObject, TestCase testCase) {
        // store intent as a file
        String fileName = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"))) + ".proto";
        try (FileWriter fileWriter = new FileWriter(CommonUtil.getRuleProtoFilePath(fileName, false))) {
            fileWriter.write(testCase.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

        jsonObject.addProperty("ruleFilePath", CommonUtil.getRuleProtoFilePath(fileName));
        jsonObject.remove("P4Testgen");
        jsonObject.remove("P4TestgenStr");

        return jsonObject;
    }

    public JsonObject toReadableJsonObject() throws IOException {
        JsonObject jsonObject = super.toJsonObject();
        if (this.testCase != null) {
            jsonObject.addProperty("P4TestgenStr", this.testCase.toString());
            jsonObject.remove("P4Testgen");
            jsonObject.remove("ruleFilePath");
        }

        return jsonObject;
    }
}
