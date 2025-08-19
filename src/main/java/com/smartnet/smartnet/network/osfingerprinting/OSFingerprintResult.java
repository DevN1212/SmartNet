package com.smartnet.smartnet.network.osfingerprinting;

public class OSFingerprintResult {
    public enum OSFamily { WINDOWS, LINUX, MACOS, BSD, UNKNOWN }

    private final String targetIp;
    private final OSFamily family;
    private final String description;
    private final double confidence;

    private final Integer ttl;
    private final Integer windowSize;
    private final String tcpOptions;

    public OSFingerprintResult(String targetIp, OSFamily family, String description,
                               double confidence, Integer ttl, Integer windowSize,
                               String tcpOptions) {
        this.targetIp = targetIp;
        this.family = family;
        this.description = description;
        this.confidence = confidence;
        this.ttl = ttl;
        this.windowSize = windowSize;
        this.tcpOptions = tcpOptions;
    }

    public String getTargetIp() { return targetIp; }
    public OSFamily getFamily() { return family; }
    public String getOsName() { return family.name(); }
    public String getDescription() { return description; }
    public double getConfidence() { return confidence; }
    public Integer getTtl() { return ttl; }
    public Integer getWindowSize() { return windowSize; }
    public String getTcpOptions() { return tcpOptions; }

    @Override
    public String toString() {
        return String.format(
                "OSFingerprintResult{target=%s, os=%s, desc=%s, conf=%.2f, ttl=%s, win=%s, opts=%s}",
                targetIp, family, description, confidence, ttl, windowSize, tcpOptions
        );
    }
}
