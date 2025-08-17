package com.smartnet.smartnet.network.ipgenerator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class IPGenerator {
    /**
     * Generates all valid IP addresses in a given CIDR block.
     */
    public List<String> generateIP(String cidr) {
        List<String> ips = new ArrayList<>();
        String[] parts = cidr.split("/");
        String baseIP = parts[0];
        int prefixLength = Integer.parseInt(parts[1]);
        int hostBits = 32 - prefixLength;
        int numberOfIPs = (int) Math.pow(2, hostBits);

        byte[] ip;
        try {
            ip = InetAddress.getByName(baseIP).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid base IP: " + baseIP);
        }

        int baseInt = ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16) | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);

        for (int i = 1; i < numberOfIPs - 1; i++) { // Skip network and broadcast
            int currentIPInt = baseInt + i;
            String ipString = String.format("%d.%d.%d.%d",
                    (currentIPInt >> 24) & 0xFF,
                    (currentIPInt >> 16) & 0xFF,
                    (currentIPInt >> 8) & 0xFF,
                    currentIPInt & 0xFF);
            ips.add(ipString);
        }

        return ips;
    }
}
