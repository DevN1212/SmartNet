package com.smartnet.smartnet.network.networkinterfacemanager;

import org.pcap4j.core.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.util.List;

public class NetworkInterfaceManager {

    private static PcapNetworkInterface defaultInterface;

    public static synchronized PcapNetworkInterface getDefaultInterface() throws Exception {
        if (defaultInterface == null) {
            defaultInterface = resolveDefaultInterface();
        }
        return defaultInterface;
    }

    private static PcapNetworkInterface resolveDefaultInterface() throws Exception {
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        if (nifs == null || nifs.isEmpty()) {
            throw new IllegalStateException("No NPF interfaces found. Is Npcap installed?");
        }

        // 1. Try to detect default local IP on Windows via "route print -4"
        String defaultLocalIp = detectDefaultLocalIpWindows();
        if (defaultLocalIp != null) {
            for (PcapNetworkInterface nif : nifs) {
                for (PcapAddress addr : nif.getAddresses()) {
                    if (addr.getAddress() instanceof Inet4Address) {
                        String a = addr.getAddress().getHostAddress();
                        if (a.equals(defaultLocalIp)) {
                            return nif;
                        }
                    }
                }
            }
        }

        // 2. Heuristic: pick non-loopback, non-virtual adapter with IPv4. Prefer Ethernet, then Wi-Fi.
        PcapNetworkInterface candidateWifi = null;
        for (PcapNetworkInterface nif : nifs) {
            String desc = nif.getDescription() != null ? nif.getDescription().toLowerCase() : "";
            String name = nif.getName() != null ? nif.getName().toLowerCase() : "";

            if (nif.isLoopBack()) continue;
            if (desc.contains("wan miniport") || name.contains("wan miniport")) continue;
            if (desc.contains("wi-fi direct") || desc.contains("virtual") || desc.contains("pseudo") ||
                    desc.contains("vmware") || desc.contains("virtualbox") || desc.contains("hyper-v") ||
                    desc.contains("bluetooth")) {
                continue;
            }

            boolean hasIPv4 = nif.getAddresses().stream()
                    .anyMatch(addr -> addr.getAddress() instanceof Inet4Address);
            if (!hasIPv4) continue;

            if (desc.contains("ethernet") || name.startsWith("eth") || name.startsWith("en")) {
                return nif; // Ethernet wins
            }

            if (candidateWifi == null && (desc.contains("wi-fi") || desc.contains("wlan") ||
                    name.startsWith("wlan") || name.startsWith("wi"))) {
                candidateWifi = nif;
            }
        }

        if (candidateWifi != null) {
            return candidateWifi;
        }

        // 3. Final fallback: first non-loopback with IPv4
        for (PcapNetworkInterface nif : nifs) {
            boolean hasIPv4 = nif.getAddresses().stream()
                    .anyMatch(addr -> addr.getAddress() instanceof Inet4Address);
            if (hasIPv4 && !nif.isLoopBack()) {
                return nif;
            }
        }

        throw new IllegalStateException("No usable IPv4 adapter found.");
    }
    public static String getDefaultInterfaceIp() throws Exception {
        PcapNetworkInterface nif = getDefaultInterface();
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() instanceof Inet4Address) {
                return addr.getAddress().getHostAddress();
            }
        }
        return null; // no IPv4 found
    }

    private static String detectDefaultLocalIpWindows() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (!os.contains("win")) return null;

            Process p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "route print -4"});
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                boolean inIpv4Table = false;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("IPv4 Route Table")) {
                        inIpv4Table = true;
                        continue;
                    }
                    if (!inIpv4Table) continue;

                    if (line.startsWith("0.0.0.0")) {
                        String[] parts = line.split("\\s+");
                        if (parts.length >= 4) {
                            return parts[3]; // local interface IP
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}

//package com.smartnet.smartnet.network.networkinterfacemanager;
//
//import org.pcap4j.core.*;
//import java.net.Inet4Address;
//import java.util.List;
//
//public class NetworkInterfaceManager {
//
//    private static PcapNetworkInterface defaultInterface;
//
//    public static synchronized PcapNetworkInterface getDefaultInterface() throws Exception {
//        if (defaultInterface == null) {
//            defaultInterface = resolveDefaultInterface();
//        }
//        return defaultInterface;
//    }
//
//    private static PcapNetworkInterface resolveDefaultInterface() throws Exception {
//        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
//        if (nifs == null || nifs.isEmpty()) {
//            throw new IllegalStateException("No NPF interfaces found. Is Npcap installed?");
//        }
//
//        for (PcapNetworkInterface nif : nifs) {
//            boolean hasIPv4 = nif.getAddresses().stream().anyMatch(addr -> addr.getAddress() instanceof Inet4Address);
//            boolean notVirtual = !nif.getDescription().toLowerCase().contains("virtual")
//                    && !nif.getDescription().toLowerCase().contains("miniport");
//            if (hasIPv4 && notVirtual) {
//                System.out.println("Auto-selected interface -> " + nif.getName() + " / " + nif.getDescription());
//                return nif;
//            }
//        }
//
//        throw new IllegalStateException("No valid physical interface with IPv4 found.");
//    }
//}
