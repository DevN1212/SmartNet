package com.smartnet.smartnet.network.utils;

import java.net.InetAddress;

public class Reachability {
    /**
     * Checks if a host is reachable using ICMP ping.
     */
    public boolean isReachable(String ipAddress) {
        try {
            InetAddress address = InetAddress.getByName(ipAddress);
            return address.isReachable(1000);
        } catch (Exception e) {
            return false;
        }
    }
}
