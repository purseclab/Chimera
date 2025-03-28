package edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api;

public class DeviceCodeCoverage extends CodeCoverage {
    private final String deviceId;

    public DeviceCodeCoverage(String deviceId, byte[] traceBits) {
        super(traceBits);
        this.deviceId = deviceId;
    }

    public DeviceCodeCoverage(DeviceCodeCoverage deviceCodeCoverage) {
        this(deviceCodeCoverage.deviceId, deviceCodeCoverage.traceBits);
    }

    @Override
    public DeviceCodeCoverage deepCopy() {
        return new DeviceCodeCoverage(this);
    }

    public String getDeviceId() {
        return deviceId;
    }

    public static String getStatsHeader() {
        return "DevCode(deviceId, hit, mapSize)";
    }

    public String getStatsString(boolean printTime) {
        StringBuilder sb = new StringBuilder();
        if (printTime) {
            sb.append(System.currentTimeMillis());
            sb.append(", ");
        }
        sb.append(deviceId);
        sb.append(", ");
        sb.append(this.getHitCount());
        sb.append(", ");
        sb.append(this.getMapSize());

        return sb.toString();
    }
}
