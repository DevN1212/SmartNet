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
    public String osName;
    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
        this(ipAddress, isReachable, openPorts, macAddress, hostName, null);
    }

    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName, String osName) {
        this.ipAddress = ipAddress;
        this.isReachable = isReachable;
        this.openPorts = openPorts;
        this.macAddress = macAddress;
        this.hostName = hostName;
        this.osName = osName;
    }
//    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
//        this.ipAddress = ipAddress;
//        this.isReachable = isReachable;
//        this.openPorts = openPorts;
//        this.macAddress = macAddress;
//        this.hostName = hostName;
//    }
//    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName,String OsName) {
//        this.ipAddress = ipAddress;
//        this.isReachable = isReachable;
//        this.openPorts = openPorts;
//        this.macAddress = macAddress;
//        this.hostName = hostName;
//        this.OsName = OsName;
//    }
}
