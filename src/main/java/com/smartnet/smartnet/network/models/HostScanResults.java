package com.smartnet.smartnet.network.models;

import java.util.List;

public class HostScanResults {
    /**
     * Represents the result of scanning a single host.
     */
    private final String ipAddress;
    private final boolean isReachable;
    private final List<Integer> openPorts;
    private final String macAddress;   // optional
    private final String hostName;
    private final String osName;       // optional

    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
        this(ipAddress, isReachable, openPorts, macAddress, hostName, null);
    }
    // Full constructor (internal use)
    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts,
                           String macAddress, String hostName, String osName) {
        this.ipAddress = ipAddress;
        this.isReachable = isReachable;
        this.openPorts = openPorts;
        this.macAddress = macAddress;
        this.hostName = hostName;
        this.osName = osName;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getHostName() {
        return hostName;
    }

    public boolean isReachable() {
        return isReachable;
    }

    public List<Integer> getOpenPorts() {
        return openPorts;
    }

    public String getOsName() {
        return osName;
    }

    public String getMacAddress() {
        return macAddress;
    }
}

//package com.smartnet.smartnet.network.models;
//
//import java.util.List;
//
//public class HostScanResults {
//    /**
//     * Represents the result of scanning a single host.
//     */
//    public final String ipAddress;
//    public final boolean isReachable;
//    public final List<Integer> openPorts;
//    public final String macAddress;
//    public final String hostName;
//    public String osName;
//    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
//        this(ipAddress, isReachable, openPorts, macAddress, hostName, null);
//    }
//
//    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName, String osName) {
//        this.ipAddress = ipAddress;
//        this.isReachable = isReachable;
//        this.openPorts = openPorts;
//        this.macAddress = macAddress;
//        this.hostName = hostName;
//        this.osName = osName;
//    }
//
//    public String getIpAddress() {
//        return ipAddress;
//    }
//
//    public String getHostName() {
//        return hostName;
//    }
//
//    public boolean isReachable() {
//        return isReachable;
//    }
//
//    public List<Integer> getOpenPorts() {
//        return openPorts;
//    }
//
//    public String getOsName() {
//        return osName;
//    }
//
//    public String getMacAddress() {
//        return macAddress;
//    }
//
//    //    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName) {
////        this.ipAddress = ipAddress;
////        this.isReachable = isReachable;
////        this.openPorts = openPorts;
////        this.macAddress = macAddress;
////        this.hostName = hostName;
////    }
////    public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress, String hostName,String OsName) {
////        this.ipAddress = ipAddress;
////        this.isReachable = isReachable;
////        this.openPorts = openPorts;
////        this.macAddress = macAddress;
////        this.hostName = hostName;
////        this.OsName = OsName;
////    }
//}
