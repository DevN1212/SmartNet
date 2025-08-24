package com.smartnet.smartnet.network.ipgenerator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class IPGenerator {
    /**
     * Generates all valid IP addresses in a given CIDR block.
     */
//    public List<String> generateIP(String cidr) {
//        List<String> ips = new ArrayList<>();
//        String[] parts = cidr.split("/");
//        String baseIP = parts[0];
//        int prefixLength = Integer.parseInt(parts[1]);
//        int hostBits = 32 - prefixLength;
//        int numberOfIPs = (int) Math.pow(2, hostBits);
//
//        byte[] ip;
//        try {
//            ip = InetAddress.getByName(baseIP).getAddress();
//        } catch (UnknownHostException e) {
//            throw new IllegalArgumentException("Invalid base IP: " + baseIP);
//        }
//
//        // Convert given base IP to int
//        int baseInt = ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16) | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
//
//        // Compute network and broadcast
//        int mask = prefixLength == 0 ? 0 : ~((1 << hostBits) - 1);
//        int networkInt = baseInt & mask;
//        int broadcastInt = networkInt + numberOfIPs - 1;
//
//        // Generate from given IP to broadcast-1
//        for (int currentIPInt = baseInt; currentIPInt < broadcastInt; currentIPInt++) {
//            String ipString = String.format("%d.%d.%d.%d",
//                    (currentIPInt >> 24) & 0xFF,
//                    (currentIPInt >> 16) & 0xFF,
//                    (currentIPInt >> 8) & 0xFF,
//                    currentIPInt & 0xFF);
//            ips.add(ipString);
//        }
//
//        return ips;
//    }
    public List<String> generateIP(String cidr){
        try {
            return getIPRange(cidr);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }
    private static List<String> getIPRange(String cidr) throws UnknownHostException {
        String[] parts = cidr.split("/");
        InetAddress inetAddress = InetAddress.getByName(parts[0]);
        int prefixLength = Integer.parseInt(parts[1]);

        byte[] addressBytes = inetAddress.getAddress();
        int ipInt = 0;
        for (byte b : addressBytes) {
            ipInt = (ipInt << 8) | (b & 0xFF);
        }

        int mask = ~((1 << (32 - prefixLength)) - 1);
        int startIP = ipInt & mask;
        int endIP = startIP | ~mask;

        List<String> ipList = new ArrayList<>();
        for (int i = startIP; i <= endIP; i++) {
            ipList.add(intToIP(i));
        }

        return ipList;
    }

    private static String intToIP(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }
}
