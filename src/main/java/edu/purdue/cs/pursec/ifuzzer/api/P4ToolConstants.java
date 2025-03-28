package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.Properties;

public class P4ToolConstants {
    public static final String P4TOOL_PROP_NAME = "p4tool.properties";
    public static final String P4TOOL_AGENT_ADDR = "p4tool.agent.ip.address";
    public static final String P4TOOL_AGENT_PORT = "p4tool.agent.port";
    public static final String P4TOOL_AGENT_NUM = "p4tool.agent.num";
    public static final String P4TOOL_AGENT_CONNECT_TRIAL_NUM = "p4tool.agent.connect.trial.num";
    public static final String P4TOOL_AGENT_PID_PATH = "p4tool.agent.pid.path";
    public static final String P4DEVICE_REMOTE_ADDR = "p4device.remote.ip.address";
    public static final String P4DEVICE_REMOTE_PORT = "p4device.remote.grpc.port";
    public static final String P4FABRIC_TNA_CLASS_PATH = "fabric.tna.class.path";
    private static final Properties properties;

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = TestUtil.class.getClassLoader().getResource(P4TOOL_PROP_NAME);
        if (url == null) throw new UncheckedIOException(new FileNotFoundException(P4TOOL_PROP_NAME));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }
    }

    public static String getP4toolAgentAddr() {
        return properties.getProperty(P4TOOL_AGENT_ADDR);
    }

    public static int getP4toolAgentPort() {
        return Integer.parseInt(properties.getProperty(P4TOOL_AGENT_PORT));
    }

    public static int getP4toolAgentNum() {
        return Integer.parseInt(properties.getProperty(P4TOOL_AGENT_NUM));
    }

    public static int getP4toolAgentConnectTrialNum() {
        return Integer.parseInt(properties.getProperty(P4TOOL_AGENT_CONNECT_TRIAL_NUM));
    }

    public static String getP4toolAgentPidPath() {
        return properties.getProperty(P4TOOL_AGENT_PID_PATH);
    }

    public static String getRemoteSwitchIP() {
        return properties.getProperty(P4DEVICE_REMOTE_ADDR);
    }

    public static String getRemoteSwitchPort() {
        return properties.getProperty(P4DEVICE_REMOTE_PORT);
    }

    public static String getFabricTnaClassPath() {
        return properties.getProperty(P4FABRIC_TNA_CLASS_PATH);
    }
}
