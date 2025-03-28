package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.util.CommonUtil;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4CoverageReplyWithError;
import edu.purdue.cs.pursec.ifuzzer.util.P4Util.P4UtilErrorType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen.OutputPacketAtPort;
import p4testgen.P4Testgen.TestCase;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public abstract class FuzzP4Guidance {
    protected static final P4Util p4UtilInstance = P4Util.getInstance();
    private static Logger log = LoggerFactory.getLogger(FuzzP4Guidance.class);
    protected final Random rand = new Random();
    List<String> failedTestgenProtoFilePathList;

    public FuzzP4Guidance() {
        failedTestgenProtoFilePathList = new ArrayList<>();
    }

    public List<String> getFailedTestgenProtoFilePathList() {
        return failedTestgenProtoFilePathList;
    }

    public boolean isInvalidTestCase(TestCase testCase, P4CoverageReplyWithError covReply) throws EndFuzzException {
        if (!covReply.isError())
            return false;

        P4UtilErrorType errorType = covReply.getErrorType();
        if (errorType.equals(P4UtilErrorType.SERVER_DOWN)) {
            throw new EndFuzzException("Cannot connect grpc");

        } else if (errorType.equals(P4UtilErrorType.UNSUPPORTED)) {
            return true;
        }

        // If request returns BUG, record the failed one
        String ruleFilePath = CommonUtil.createRuleProtoFilePath(false);
        try (FileWriter fileWriter = new FileWriter(ruleFilePath)) {
            fileWriter.write(testCase.toString());
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }

        failedTestgenProtoFilePathList.add(ruleFilePath);
        return true;
    }

    public boolean isInvalidOutputPort(TestCase testCase) {
        if (ConfigConstants.CONFIG_P4_MAX_ALLOW_PORT_NUM == 0 ||
                testCase.getExpectedOutputPacketCount() < 0)
            return false;

        for (OutputPacketAtPort outputPacketAtPort : testCase.getExpectedOutputPacketList()) {
            int outPort = outputPacketAtPort.getPort();
            // check whether outPort is in valid range
            if (outPort > ConfigConstants.CONFIG_P4_MAX_ALLOW_PORT_NUM &&
                    outputPacketAtPort.getPort() != ConfigConstants.CONFIG_P4_CONTROLLER_PORT) {
                log.warn("Port {} is not allowed", outPort);
                return true;
            }
        }
        return false;
    }
}
