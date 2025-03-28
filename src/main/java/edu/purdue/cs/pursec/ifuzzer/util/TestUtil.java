package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.protobuf.TextFormat;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.packet.api.DpAgentProxy;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.HostToHostIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ResourcePoint;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.ConfigTopo;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import org.apache.commons.net.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import p4testgen.P4Testgen;
import p4testgen.P4Testgen.TestCase;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

public class TestUtil {
    private static Logger log = LoggerFactory.getLogger(TestUtil.class);
    private static final Properties properties;

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = TestUtil.class.getClassLoader().getResource(TestConstants.TEST_PROP_NAME);
        if (url == null) throw new UncheckedIOException(new FileNotFoundException(TestConstants.TEST_PROP_NAME));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }
    }

    public static int getTestAgentPid() {
        Path path = TestUtil.getTestAgentFilePath();

        if (!Files.isReadable(path))
            return -1;

        int ret = -1;
        try {
            ret = Integer.parseInt(Files.readAllLines(path).get(0));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public static JsonObject fromJson(String jsonStr) throws JsonSyntaxException, JsonIOException {
        JsonReader jsonReader = new JsonReader(new StringReader(jsonStr));
        return JsonParser.parseReader(jsonReader).getAsJsonObject();
    }

    public static JsonObject fromJson(Reader reader) throws JsonSyntaxException, JsonIOException {
        return JsonParser.parseReader(new JsonReader(reader)).getAsJsonObject();
    }

    public static JsonObject getJsonResultFromHttpConnection(HttpURLConnection conn)
            throws IOException, JsonSyntaxException, JsonIOException {
        String response = "";
        Scanner scanner = new Scanner(conn.getInputStream());
        while (scanner.hasNextLine()) {
            response += scanner.nextLine();
            response += "\n";
        }
        scanner.close();

        return TestUtil.fromJson(response);
    }

    public static Path getTestAgentFilePath() {
        return Paths.get(properties.getProperty(TestConstants.TEST_AGENT_PID_FILE));
    }

    public static String getTestAgentLogRoot() {
        return properties.getProperty(TestConstants.TEST_AGENT_LOG_ROOT);
    }

    private static boolean isThisMyIpAddress(InetAddress inetAddress) {
        if (inetAddress.isAnyLocalAddress() || inetAddress.isLoopbackAddress())
            return true;

        try {
            return (NetworkInterface.getByInetAddress(inetAddress) != null);
        } catch (SocketException e) {
            return false;
        }
    }

    public static boolean isLocalTestAgent() throws UnknownHostException {
        String ipAddr = properties.getProperty(TestConstants.TEST_AGENT_ADDR);
        return isThisMyIpAddress(InetAddress.getByName(ipAddr));
    }

    public static String getTestAgentRestURL(String ipAddress, String port, String path) {
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append("http://").append(ipAddress).append(":").append(port).append(path);
        return urlBuilder.toString().replaceAll("\\s+", "");
    }

//    public static boolean requestTopoOperation(TopoOperation operation, String actionId) throws IOException {
//        return requestTopoOperation(operation.getRequestUrl(), operation.getElemType(),
//                operation.getElem().toJson(), actionId);
//    }

    public static HttpURLConnection requestTopoOperation(String command, String elemType, JsonObject elemJson, String actionId) throws IOException {
        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/" + elemType + "/" + command);

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(TopoOperation.getRequestMethod(command));
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        if (actionId != null)
            elemJson.addProperty("actionId", actionId);

        os.write(elemJson.toString().getBytes("utf-8"));
        log.debug(elemJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestPingAll() throws IOException {
        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/pingall");

        // Request TOPOLOGY REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

//        int responseCode = conn.getResponseCode();
//        if (responseCode >= 200 && responseCode < 300)
//            return true;
//
//        return false;
        return conn;
    }

    public static boolean requestPing(TopoHost one, TopoHost two) throws IOException {
        return requestPing(one.getAddr(), two.getAddr());
    }

    public static boolean requestPing(String oneIp, String twoIp) throws IOException {
        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/ping");

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        //byte[] input = intent.toJson().toString().getBytes("utf-8");
        JsonObject testJson = new JsonObject();
        testJson.addProperty("src", oneIp);
        testJson.addProperty("dst", twoIp);

        testJson.addProperty("key", "cliCommand");
        testJson.addProperty("actionId", "cliCommand-001");

        os.write(testJson.toString().getBytes("utf-8"));
        log.debug(testJson.toString());
        os.close();

        int responseCode = conn.getResponseCode();

        return (responseCode >= 200 && responseCode < 300);
    }

    public static HttpURLConnection requestSniffStart(String key, int seq, String actionId) throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/sniff_start");

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        //byte[] input = intent.toJson().toString().getBytes("utf-8");
        JsonObject testJson = new JsonObject();
        testJson.addProperty("key", key);
        testJson.addProperty("actionId", actionId);
        testJson.addProperty("seq", String.valueOf(seq));

        os.write(testJson.toString().getBytes("utf-8"));
        log.debug(testJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestSniffStop(String key, int seq, String actionId) throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/sniff_stop");

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        //byte[] input = intent.toJson().toString().getBytes("utf-8");
        JsonObject testJson = new JsonObject();
        testJson.addProperty("key", key);
        testJson.addProperty("actionId", actionId);
        testJson.addProperty("seq", String.valueOf(seq));

        os.write(testJson.toString().getBytes("utf-8"));
        log.debug(testJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestTest(@Nonnull JsonObject testJson, String intentEventKey, int seq,
                                                String actionId, String route) throws IOException {

        // TODO: define what is correct key of intent? (UUID or intentId in scenario)
        testJson.addProperty("key", intentEventKey);
        testJson.addProperty("actionId", actionId);
        testJson.addProperty("seq", String.valueOf(seq));

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                route);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();

        os.write(testJson.toString().getBytes("utf-8"));
        log.debug(testJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestPacketTest(String deviceId, P4Testgen.InputPacketAtPort inputPacketAtPort,
                                                      List<P4Testgen.OutputPacketAtPort> outputPacketAtPortList,
                                                      String key, int seq, String actionId) throws IOException {

        JsonObject testJson = new JsonObject();
        testJson.addProperty("deviceId", deviceId);
        testJson.addProperty("inPort", String.valueOf(inputPacketAtPort.getPort()));
        testJson.addProperty("inPacket",
                Base64.encodeBase64String(inputPacketAtPort.getPacket().toByteArray()));
        testJson.addProperty("actionId", actionId);

        testJson.addProperty("key", key);
        testJson.addProperty("seq", String.valueOf(seq));
        testJson.addProperty("ret_url", TestConstants.TEST_MANAGER_URL +
                TestConstants.TEST_PACKET_RET_ROUTE);

        JsonArray outPacketJsonArr = new JsonArray();
        for (P4Testgen.OutputPacketAtPort outputPacketAtPort : outputPacketAtPortList) {
            JsonObject outPacketJson = new JsonObject();
            int outPort = outputPacketAtPort.getPort();
            byte[] outPacketBytes = outputPacketAtPort.getPacket().toByteArray();
            byte[] outPacketMaskBytes = outputPacketAtPort.getPacketMask().toByteArray();
            log.debug("Test has out packet len:{} at port:{}", outPacketBytes.length, outPort);
            outPacketJson.addProperty("outPort", String.valueOf(outPort));
            outPacketJson.addProperty("outPacket",
                    Base64.encodeBase64String(outPacketBytes));
            outPacketJson.addProperty("outPacketMask",
                    Base64.encodeBase64String(outPacketMaskBytes));
            outPacketJsonArr.add(outPacketJson);
        }
        testJson.add("output", outPacketJsonArr);
        testJson.addProperty("wait_millisec", CommonUtil.getRuntimeConfigP4PacketWaitMs());

        if (CommonUtil.isRuntimeConfigTTFMode()) {
            testJson.addProperty("ttf_mode", true);
        }

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/packet");

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();

        os.write(testJson.toString().getBytes("utf-8"));
        os.close();
        log.trace(testJson.toString());

        return conn;
    }

    public static HttpURLConnection requestPazzResult(String intentEventKey, int seq,
                                                String actionId) throws IOException {

        JsonObject testJson = new JsonObject();

        testJson.addProperty("key", intentEventKey);
        testJson.addProperty("actionId", actionId);
        testJson.addProperty("seq", String.valueOf(seq));

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/pazz_result");

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(1000);

        OutputStream os = conn.getOutputStream();

        os.write(testJson.toString().getBytes("utf-8"));
        log.debug(testJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestSend(@Nonnull JsonObject testJson, DpAgentProxy dpAgentProxy) throws IOException {

        String url = TestUtil.getTestAgentRestURL(dpAgentProxy.getMgmt(),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/send");

        String iface = dpAgentProxy.getIface();
        if (iface != null && !iface.isEmpty())
            testJson.addProperty("iface", iface);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();

        os.write(testJson.toString().getBytes("utf-8"));
        //log.debug(testJson.toString());
        os.close();

        return conn;
    }

    public static HttpURLConnection requestTopology() throws IOException {
        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/topology");

        // Request TOPOLOGY REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    public static String requestConfigTopo(ConfigTopo configTopo) throws IOException {
        HttpURLConnection conn = TestUtil.requestTopology();
        int responseCode = conn.getResponseCode();
        if (responseCode < 200 || responseCode >= 300)
            return "response: " + responseCode;

        JsonObject jsonObject = getJsonResultFromHttpConnection(conn);

        String errorMsg = jsonToConfigTopo(configTopo, jsonObject);
        if (errorMsg != null)
            return errorMsg;

        // compare configure
        if (jsonObject.has("configTopo")) {
            JsonObject configTopoJson = jsonObject.get("configTopo").getAsJsonObject();
            if (!configTopo.compareConfig(configTopoJson))
                return ("[Error] different configuration (" + configTopoJson.toString() +
                        " vs " + configTopo.getConfig().toString() + ")");
        }

        return null;
    }

    public static JsonObject requestNetCfgJson() throws IOException {
        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                "/netcfg");

        // Request TOPOLOGY REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        int responseCode = conn.getResponseCode();
        if (responseCode < 200 || responseCode >= 300)
            return null;

        return getJsonResultFromHttpConnection(conn);
    }

    public static HttpURLConnection requestDumpCov(String deviceId) throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                TestConstants.TEST_DUMP_COV_ROUTE + "/" + deviceId);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    public static HttpURLConnection requestDumpCov() throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                TestConstants.TEST_DUMP_COV_ROUTE);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    public static HttpURLConnection requestClearCov(String deviceId) throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                TestConstants.TEST_CLEAR_COV_ROUTE + "/" + deviceId);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    public static HttpURLConnection requestClearCov() throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                TestConstants.TEST_CLEAR_COV_ROUTE);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    private static HttpURLConnection requestDumpRuleHttp(String deviceId) throws IOException {

        String url = TestUtil.getTestAgentRestURL(
                properties.getProperty(TestConstants.TEST_AGENT_ADDR),
                properties.getProperty(TestConstants.TEST_AGENT_PORT),
                TestConstants.TEST_DUMP_RULE_ROUTE + "/" + deviceId);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(1000);

        return conn;
    }

    public static P4Testgen.TestCase requestDumpRule(String deviceId) throws IOException {
        HttpURLConnection conn = requestDumpRuleHttp(deviceId);
        if (conn.getResponseCode() < 200 || conn.getResponseCode() >= 300) {
            log.warn("Error in requesting clear coverage of devices");
            return null;
        }

        JsonObject ruleJson = TestUtil.getJsonResultFromHttpConnection(conn);
        if (ruleJson.has("message")) {
            log.warn("Message from test-agent {}", ruleJson.get("message").getAsString());
            return null;
        } else if (!ruleJson.has("entities")) {
            log.warn("No field entities");
            return null;
        }

        return TextFormat.parse(ruleJson.get("entities").getAsString(), P4Testgen.TestCase.class);
    }

    public static String jsonToConfigTopo(ConfigTopo configTopo, JsonObject jsonObject) {
        if (!jsonObject.has("topology"))
            return "[Error] no topology in json";

        JsonObject topoJson = jsonObject.get("topology").getAsJsonObject();
        if (topoJson.has("devices")) {
            JsonArray devicesJson = topoJson.get("devices").getAsJsonArray();
            for (JsonElement deviceJsonElem : devicesJson) {
                JsonObject deviceJson = deviceJsonElem.getAsJsonObject();
                if (deviceJson.has("id")) {
                    configTopo.checkDevice(deviceJson.get("id").getAsString());
                }
            }
        }

        if (topoJson.has("links")) {
            JsonArray linksJson = topoJson.get("links").getAsJsonArray();
            for (JsonElement linkJsonElem : linksJson) {
                JsonObject linkJson = linkJsonElem.getAsJsonObject();
                String srcId = null, dstId = null;
                String srcPort = null, dstPort = null;
                if (linkJson.has("src")) {
                    JsonObject srcJson = linkJson.get("src").getAsJsonObject();
                    if (srcJson.has("device"))
                        srcId = srcJson.get("device").getAsString();
                    if (srcJson.has("port"))
                        srcPort = srcJson.get("port").getAsString();
                }

                if (linkJson.has("dst")) {
                    JsonObject dstJson = linkJson.get("dst").getAsJsonObject();
                    if (dstJson.has("device"))
                        dstId = dstJson.get("device").getAsString();
                    if (dstJson.has("port"))
                        dstPort = dstJson.get("port").getAsString();
                }

                configTopo.checkLink(srcId, dstId, srcPort, dstPort);
            }

            if (linksJson.size() == 0) {
                configTopo.disableCheckLink();
            }
        }

        if (topoJson.has("hosts")) {
            JsonArray hostsJson = topoJson.get("hosts").getAsJsonArray();
            for (JsonElement hostJsonElem : hostsJson) {
                JsonObject hostJson = hostJsonElem.getAsJsonObject();
                if (hostJson.has("mac"))
                    configTopo.checkHost(hostJson.get("mac").getAsString());
            }
        }

        if (topoJson.has("operations")) {
            JsonArray operationsJson = topoJson.get("operations").getAsJsonArray();
            for (JsonElement operationsJsonElem : operationsJson) {
                JsonObject operationJson = operationsJsonElem.getAsJsonObject();
                // TODO
            }
        }

        return null;
    }

    public static String storeGraph(TopoGraph topoGraph, JsonObject jsonObject) {
        if (!jsonObject.has("topology"))
            return "[Error] no topology in json";

        JsonObject topoJson = jsonObject.get("topology").getAsJsonObject();
        if (topoJson.has("devices")) {
            JsonArray devicesJson = topoJson.get("devices").getAsJsonArray();
            for (JsonElement deviceJsonElem : devicesJson) {
                JsonObject deviceJson = deviceJsonElem.getAsJsonObject();
                topoGraph.addNode(new TopoDevice(deviceJson));
            }
        }

        if (topoJson.has("links")) {
            JsonArray linksJson = topoJson.get("links").getAsJsonArray();
            for (JsonElement linkJsonElem : linksJson) {
                JsonObject linkJson = linkJsonElem.getAsJsonObject();
                topoGraph.addEdge(new TopoLink(linkJson));
            }
        }

        if (topoJson.has("hosts")) {
            JsonArray hostsJson = topoJson.get("hosts").getAsJsonArray();
            for (JsonElement hostJsonElem : hostsJson) {
                JsonObject hostJson = hostJsonElem.getAsJsonObject();
                TopoHost newHost = new TopoHost(hostJson, true);
                topoGraph.addNode(newHost);
                String deviceId;
                if (!hostJson.has("device"))
                    continue;
                else
                    deviceId = hostJson.get("device").getAsString();

                String portNo = "0";
                if (hostJson.has("port"))
                    portNo = hostJson.get("port").getAsString();

                topoGraph.addEdge(new TopoHostEdge(deviceId, newHost.getId(), portNo, null));
                topoGraph.addEdge(new TopoHostEdge(newHost.getId(), deviceId, null, portNo));
            }
        }

        if (topoJson.has("operations")) {
            JsonArray operationsJson = topoJson.get("operations").getAsJsonArray();
            for (JsonElement operationsJsonElem : operationsJson) {
                JsonObject operationJson = operationsJsonElem.getAsJsonObject();
                // TODO
            }
        }

        return null;
    }

    public static State getExpectedStateFromIntent(TopoGraph topoGraph, Intent intent) {

        if (intent instanceof HostToHostIntent) {
            HostToHostIntent hIntent = (HostToHostIntent) intent;

            TopoNode src = topoGraph.getNode(hIntent.getSrc().getHostId());
            TopoNode dst = topoGraph.getNode(hIntent.getDst().getHostId());

            if (src == null || dst == null)
                return State.FAILED;

            // TODO: priority check (test all intents; build all subgraphs?)
            if (src.getId().equals(dst.getId()))
                return State.FAILED;

            if (topoGraph.pathExists(src, dst, true))
                return State.INSTALLED;

            return State.FAILED;

        } else if (intent instanceof ReachabilityIntent) {
            ReachabilityIntent rIntent = (ReachabilityIntent) intent;

            /*
             * NOTE: Calculate all path [src] x [dst]
             *       If there is a node connected to source point, it is a source.
             *       Otherwise, device of source point is a source.
             */
            List<ResourceElem> srcList = rIntent.getSrcList();
            List<ResourceElem> dstList = rIntent.getDstList();

            log.debug("srcList and dstList have {}, {} member(s)", srcList.size(), dstList.size());
            log.debug("Graph: {} devices, {} edges, {} links", topoGraph.getAllDevices().size(),
                    topoGraph.getAllEdges().size(), topoGraph.getAllLinks().size());

            // Assertion
            if (srcList.isEmpty() || dstList.isEmpty())
                return State.FAILED;

            TopoNode src, dst;
            for (ResourceElem srcElem : srcList) {
                ResourcePoint srcPoint = (ResourcePoint) srcElem;
//                TopoEdge srcEdge = graph.getEdgeFromDst(srcPoint.getDeviceId(), srcPoint.getPortNo());
//
//                if (srcEdge != null)
//                    src = graph.getNode(srcEdge.getSrcId());
//                else
                src = topoGraph.getNode(srcPoint.getDeviceId().toLowerCase());

                // Not found
                if (src == null) {
                    log.info("src is not found");
                    return State.FAILED;
                }
                log.debug("  src: {}", src.toString());

                for (ResourceElem dstElem : dstList) {
                    ResourcePoint dstPoint = (ResourcePoint) dstElem;
//                    TopoEdge dstEdge = graph.getEdgeFromSrc(dstPoint.getDeviceId(), dstPoint.getPortNo());
//                    if (dstEdge != null)
//                        dst = graph.getNode(dstEdge.getDstId());
//                    else
                    dst = topoGraph.getNode(dstPoint.getDeviceId().toLowerCase());

                    // Not found
                    if (dst == null) {
                        log.info("dst is not found");
                        return State.FAILED;
                    }
                    log.debug("  dst: {}", dst.toString());

                    // Cannot find the path
                    if (!topoGraph.pathExists(src, dst)) {
                        log.info("src-to-dst path is not found");
                        return State.FAILED;
                    }
                }
            }

            return State.INSTALLED;
        }

        return State.FAILED;
    }
}
