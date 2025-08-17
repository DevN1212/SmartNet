package com.smartnet.smartnet.network.models;

import java.util.List;

public class HostScanResults {
    /**
     * Represents the result of scanning a single host.
     */
    public final String ipAddress;
    public final boolean isReachable;
    public final List<Integer> openPorts;
    public final String macAddress;
    public final String hostName;
    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
        this.ipAddress = ipAddress;
        this.isReachable = isReachable;
        this.openPorts = openPorts;
        this.macAddress = macAddress;
        this.hostName = hostName;
    }
}
