package com.smartnet.smartnet.network.osfingerprinting;

import com.smartnet.smartnet.network.networkinterfacemanager.NetworkInterfaceManager;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import com.smartnet.smartnet.network.osfingerprinting.OSFingerprintResult.OSFamily;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeoutException;

public class OSFingerprintService {

    public static class Config {
        public List<Integer> probePorts = Arrays.asList(80, 443, 22);
        public int readTimeoutMillis = 1500;
        public int snapLen = 65536;
        public int waitPerTargetMillis = 2000;
        public boolean verbose = false;
        public boolean usePromiscuous = false; // default NONPROMISCUOUS
        public InetAddress preferredSrcAddress = null;
    }

    private final Config cfg;
    private final PcapNetworkInterface nif;

    public OSFingerprintService() throws Exception { this.cfg = new Config();this.nif= NetworkInterfaceManager.getDefaultInterface();
    }
    public OSFingerprintService(Config cfg) throws Exception{ this.cfg = cfg;this.nif=NetworkInterfaceManager.getDefaultInterface(); }

    public OSFingerprintResult fingerprint(String targetIp) throws Exception {
        InetAddress dst = InetAddress.getByName(targetIp);

        if (nif == null) {
            throw new IllegalStateException("No suitable network interface found for " + targetIp);
        }

        if (cfg.verbose) {
            System.out.println("Using interface: " + nif.getName() + " / " + nif.getDescription());
        }

        PcapNetworkInterface.PromiscuousMode mode =
                cfg.usePromiscuous
                        ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                        : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;

        try (PcapHandle handle = nif.openLive(cfg.snapLen, mode, cfg.readTimeoutMillis)) {
            String bpf = "ip and (tcp or icmp) and host " + targetIp;
            handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);

            // Send probes
            for (int port : cfg.probePorts) {
                sendTcpSyn(handle, nif, dst, port);
            }

            long end = System.currentTimeMillis() + cfg.waitPerTargetMillis;
            Integer ttl = null;
            Integer windowSize = null;
            String tcpOptions = null;

            while (System.currentTimeMillis() < end) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet == null) continue;

                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ip = packet.get(IpV4Packet.class);
                        ttl = ip.getHeader().getTtlAsInt();

                        if (packet.contains(TcpPacket.class)) {
                            TcpPacket tcp = packet.get(TcpPacket.class);
                            windowSize = tcp.getHeader().getWindowAsInt();
                            tcpOptions = String.valueOf(tcp.getHeader().getOptions());
                            break; // got what we need
                        }
                    }
                } catch (TimeoutException ignored) {}
            }

            // --- Refined OS heuristic (uses TTL + Window size rules you supplied) ---
            OSFamily osFamily = OSFamily.UNKNOWN;
            String desc = "No strong match";
            double conf = 0.3;

            if (ttl != null && windowSize != null) {
                // Windows: TTL ~128, Win 65535 (64KB)
                if (ttl >= 120 && ttl <= 130 && windowSize == 65535) {
                    osFamily = OSFamily.WINDOWS;
                    desc = "Windows Server (TTL~128, Win=65535)";
                    conf = 0.95;
                }
                // Linux server: TTL ~64, Win 65535
                else if (ttl >= 60 && ttl <= 70 && windowSize == 65535) {
                    osFamily = OSFamily.LINUX;
                    desc = "Linux (TTL~64, Win=65535)";
                    conf = 0.9;
                }
                // FreeBSD: TTL ~64, Win 32768
                else if (ttl >= 60 && ttl <= 70 && windowSize == 32768) {
                    osFamily = OSFamily.BSD; // using BSD enum for FreeBSD
                    desc = "FreeBSD (TTL~64, Win=32768)";
                    conf = 0.9;
                }
                // Solaris/AIX/Cisco devices: TTL ~255
                else if (ttl >= 240 && ttl <= 255) {
                    if (windowSize == 65535) {
                        osFamily = OSFamily.MACOS; // reuse MACOS enum for Solaris/AIX-like
                        desc = "Solaris/AIX-like (TTL~255, Win=65535)";
                        conf = 0.9;
                    } else if (windowSize == 16384) {
                        osFamily = OSFamily.BSD; // Cisco/AIX routers often show 16384
                        desc = "Cisco/AIX-like (TTL~255, Win=16384)";
                        conf = 0.85;
                    }
                }
                // If TTL matches 64 and window is one of common Linux multiples, nudge Linux
                else if (ttl >= 60 && ttl <= 70) {
                    if (windowSize == 5840 || windowSize == 29200 || windowSize == 64240) {
                        osFamily = OSFamily.LINUX;
                        desc = "Linux-like (TTL~64, win=" + windowSize + ")";
                        conf = 0.7;
                    }
                }
            }

            return new OSFingerprintResult(targetIp, osFamily, desc, conf, ttl, windowSize, tcpOptions);
        }
    }

    // --- Helpers ---

    private void sendTcpSyn(PcapHandle handle, PcapNetworkInterface nif,
                            InetAddress dst, int dstPort) throws Exception {

        // Source IPv4 from selected interface
        Inet4Address srcAddr = null;
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() instanceof Inet4Address) {
                srcAddr = (Inet4Address) addr.getAddress();
                break;
            }
        }
        if (srcAddr == null) {
            throw new IllegalStateException("No IPv4 address for interface " + nif.getName());
        }

        // Source MAC
        if (nif.getLinkLayerAddresses() == null || nif.getLinkLayerAddresses().isEmpty()) {
            throw new IllegalStateException("No link-layer (MAC) address found for " + nif.getName());
        }
        MacAddress srcMac = (MacAddress) nif.getLinkLayerAddresses().get(0);

        // Destination MAC via your resolver
        com.smartnet.smartnet.network.macutils.Mac macResolver =
                new com.smartnet.smartnet.network.macutils.Mac();
        String dstMacStr = macResolver.resolveMac(dst.getHostAddress());
        MacAddress dstMac = null;
        if (dstMacStr != null && !"Unknown".equalsIgnoreCase(dstMacStr)) {
            dstMac = toMacAddress(dstMacStr);
        }
        if (dstMac == null) {
            // fallback to broadcast if ARP fails (still lets the frame out on L2)
            dstMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
        }

        // TCP builder — include pseudo-header IPs for checksum
        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
        tcpBuilder
                .srcPort(new TcpPort((short) ThreadLocalRandom.current().nextInt(1025, 65535), ""))
                .dstPort(new TcpPort((short) dstPort, ""))
                .syn(true)
                .window((short) 64240)
                .sequenceNumber(ThreadLocalRandom.current().nextInt())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .srcAddr(srcAddr)
                .dstAddr((Inet4Address) dst);

        // IPv4 builder
        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(srcAddr)
                .dstAddr((Inet4Address) dst)
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        // Ethernet frame
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(dstMac)
                .srcAddr(srcMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);

        handle.sendPacket(etherBuilder.build());
    }

    /** Normalize various MAC formats into something MacAddress can parse. */
    private MacAddress toMacAddress(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toLowerCase();
        if (s.contains("-")) s = s.replace('-', ':');
        try {
            return MacAddress.getByName(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

//package com.smartnet.smartnet.network.osfingerprinting;
//
//import org.pcap4j.core.*;
//import org.pcap4j.packet.*;
//import org.pcap4j.packet.namednumber.*;
//import org.pcap4j.util.MacAddress;
//import com.smartnet.smartnet.network.osfingerprinting.OSFingerprintResult.OSFamily;
//
//import java.net.Inet4Address;
//import java.net.InetAddress;
//import java.util.*;
//import java.util.concurrent.ThreadLocalRandom;
//import java.util.concurrent.TimeoutException;
//
//public class OSFingerprintService {
//
//    public static class Config {
//        public List<Integer> probePorts = Arrays.asList(80, 443, 22);
//        public int readTimeoutMillis = 1500;
//        public int snapLen = 65536;
//        public int waitPerTargetMillis = 2000;
//        public boolean verbose = false;
//        public boolean usePromiscuous = false; // default NONPROMISCUOUS
//        public InetAddress preferredSrcAddress = null;
//    }
//
//    private final Config cfg;
//
//    public OSFingerprintService() { this.cfg = new Config(); }
//    public OSFingerprintService(Config cfg) { this.cfg = cfg; }
//
//    public OSFingerprintResult fingerprint(String targetIp) throws Exception {
//        InetAddress dst = InetAddress.getByName(targetIp);
//        PcapNetworkInterface nif = chooseInterfaceForTarget(dst, cfg.preferredSrcAddress);
//        if (nif == null) {
//            throw new IllegalStateException("No suitable network interface found for " + targetIp);
//        }
//
//        if (cfg.verbose) {
//            System.out.println("Using interface: " + nif.getName() + " / " + nif.getDescription());
//        }
//
//        PcapNetworkInterface.PromiscuousMode mode =
//                cfg.usePromiscuous
//                        ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
//                        : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
//
//        try (PcapHandle handle = nif.openLive(cfg.snapLen, mode, cfg.readTimeoutMillis)) {
//            String bpf = "ip and (tcp or icmp) and host " + targetIp;
//            handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
//
//            // Send probes
//            for (int port : cfg.probePorts) {
//                sendTcpSyn(handle, nif, dst, port);
//            }
//
//            long end = System.currentTimeMillis() + cfg.waitPerTargetMillis;
//            Integer ttl = null;
//            Integer windowSize = null;
//            String tcpOptions = null;
//
//            while (System.currentTimeMillis() < end) {
//                try {
//                    Packet packet = handle.getNextPacketEx();
//                    if (packet == null) continue;
//
//                    if (packet.contains(IpV4Packet.class)) {
//                        IpV4Packet ip = packet.get(IpV4Packet.class);
//                        ttl = ip.getHeader().getTtlAsInt();
//
//                        if (packet.contains(TcpPacket.class)) {
//                            TcpPacket tcp = packet.get(TcpPacket.class);
//                            windowSize = tcp.getHeader().getWindowAsInt();
//                            tcpOptions = String.valueOf(tcp.getHeader().getOptions());
//                            break; // got what we need
//                        }
//                    }
//                } catch (TimeoutException ignored) {}
//            }
//
//            // Heuristic
////            OSFamily osFamily = OSFamily.UNKNOWN;
////            String desc = "No strong match";
////            double conf = 0.3;
////
////            if (ttl != null && windowSize != null) {
////                if (ttl >= 120 && ttl <= 130) {
////                    if (windowSize == 8192 || windowSize == 65535) {
////                        osFamily = OSFamily.WINDOWS;
////                        desc = "Typical Windows signature";
////                        conf = 0.8;
////                    }
////                } else if (ttl >= 60 && ttl <= 70) {
////                    if (windowSize == 5840 || windowSize == 29200 || windowSize == 64240) {
////                        osFamily = OSFamily.LINUX;
////                        desc = "Typical Linux signature";
////                        conf = 0.8;
////                    }
////                } else if (ttl >= 250) {
////                    osFamily = OSFamily.MACOS;
////                    desc = "Typical macOS signature";
////                    conf = 0.7;
////                }
////            }
//            OSFamily osFamily = OSFamily.UNKNOWN;
//            String desc = "No strong match";
//            double conf = 0.3;
////            if (ttl >= 120 && ttl <= 130) {
////                if (windowSize == 65535) {
////                    osFamily=OSFamily.WINDOWS; // Windows Server 2012+
////                }
////            } else if (ttl >= 60 && ttl <= 70) {
////                if (windowSize == 65535) {
////                    osFamily=OSFamily.LINUX; // Linux modern kernels
////                } else if (windowSize == 32768) {
////                    osFamily=OSFamily.FREEBSD; // FreeBSD
////                }
////            } else if (ttl >= 240 && ttl <= 255) {
////                if (windowSize == 65535) {
////                    osFamily=OSFamily.MACOS; // Solaris / AIX
////                } else if (windowSize == 16384) {
////                    osFamily=OSFamily.BSD; // Cisco / AIX routers
////                }
////            }
//            if (ttl != null && windowSize != null) {
//                if (ttl >= 120 && ttl <= 130) {
//                    // Likely Windows
//                    if (windowSize == 8192 || windowSize == 16384 || windowSize == 65535) {
//                        osFamily = OSFamily.WINDOWS;
//                        desc = "Windows (TTL ~128)";
//                        conf = 0.9;
//                    }
//                } else if (ttl >= 60 && ttl <= 70) {
//                    // Unix-like family (Linux/macOS/BSD)
//                    if (windowSize == 5840 || windowSize == 29200 || windowSize == 64240) {
//                        osFamily = OSFamily.LINUX;
//                        desc = "Linux (TTL ~64, win=" + windowSize + ")";
//                        conf = 0.85;
//                    } else if (windowSize == 65535) {
//                        osFamily = OSFamily.MACOS;
//                        desc = "macOS / iOS (TTL ~64, win=65535)";
//                        conf = 0.85;
//                    } else if (windowSize == 16384) {
//                        osFamily = OSFamily.BSD;
//                        desc = "BSD-like system (TTL ~64, win=16384)";
//                        conf = 0.8;
//                    }
//                }
//            }
//
//            return new OSFingerprintResult(targetIp, osFamily, desc, conf, ttl, windowSize, tcpOptions);
//        }
//    }
//
//    // --- Helpers ---
//
//    /** Force-select interface #6 (Wireshark numbering = 1-based → index 5). */
////    private PcapNetworkInterface chooseInterfaceForTarget(InetAddress dst, InetAddress preferred) throws Exception {
////        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
////        int requested = 6; // your desired interface number
////        if (nifs == null || nifs.isEmpty()) {
////            throw new IllegalStateException("No NPF interfaces found. Is Npcap installed?");
////        }
////        if (requested < 1 || requested > nifs.size()) {
////            throw new IllegalArgumentException("Interface " + requested + " not found. Total: " + nifs.size());
////        }
////        PcapNetworkInterface nif = nifs.get(requested);
////        if (cfg.verbose) {
////            System.out.println("Forcing interface #" + requested + " -> " + nif.getName() + " / " + nif.getDescription());
////        }
////        return nif;
////    }
//    private PcapNetworkInterface chooseInterfaceForTarget(InetAddress dst, InetAddress preferred) throws Exception {
//        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
//        if (nifs == null || nifs.isEmpty()) {
//            throw new IllegalStateException("No NPF interfaces found. Is Npcap installed?");
//        }
//
////        PcapNetworkInterface chosen = null;
////
////        // 1. Prefer adapter that matches "preferred" IP (if provided)
////        if (preferred != null) {
////            for (PcapNetworkInterface nif : nifs) {
////                for (PcapAddress addr : nif.getAddresses()) {
////                    if (addr.getAddress() != null && addr.getAddress().equals(preferred)) {
////                        chosen = nif;
////                        break;
////                    }
////                }
////                if (chosen != null) break;
////            }
////        }
////
////        // 2. Otherwise, auto-select the main Ethernet adapter
////        if (chosen == null) {
////            for (PcapNetworkInterface nif : nifs) {
////                String desc = nif.getDescription() != null ? nif.getDescription().toLowerCase() : "";
////                String name = nif.getName().toLowerCase();
////                if (desc.contains("ethernet") || name.startsWith("eth") || name.startsWith("en")) {
////                    chosen = nif;
////                    break;
////                }
////            }
////        }
////
////        // 3. Fallback: first non-loopback adapter
////        if (chosen == null) {
////            for (PcapNetworkInterface nif : nifs) {
////                if (!nif.isLoopBack()) {
////                    chosen = nif;
////                    break;
////                }
////            }
////        }
////
////        if (chosen == null) {
////            throw new IllegalStateException("No suitable Ethernet interface found!");
////        }
////
////        if (cfg.verbose) {
////            System.out.println("Auto-selected interface -> " + chosen.getName() + " / " + chosen.getDescription());
////        }
////
////        return chosen;
//        PcapNetworkInterface chosen = null;
//
//// Step 1: require IPv4
//        for (PcapNetworkInterface nif : nifs) {
//            String desc = nif.getDescription() != null ? nif.getDescription().toLowerCase() : "";
//            String name = nif.getName().toLowerCase();
//
//            // Hard skip unwanted adapters
//            if (nif.isLoopBack()) continue;
//            if (desc.contains("wan miniport") || name.contains("wan miniport")) continue;
//            if (desc.contains("virtual") || desc.contains("pseudo") || desc.contains("bluetooth")) continue;
//
//            // Check for IPv4
//            boolean hasIPv4 = false;
//            for (PcapAddress addr : nif.getAddresses()) {
//                if (addr.getAddress() instanceof Inet4Address) {
//                    hasIPv4 = true;
//                    break;
//                }
//            }
//            if (!hasIPv4) continue;
//
//            // Step 2: prioritize Ethernet
//            if (desc.contains("ethernet") || name.startsWith("eth")) {
//                chosen = nif;
//                break;
//            }
//
//            // Step 3: fallback to Wi-Fi
//            if (chosen == null && (desc.contains("wi-fi") || desc.contains("wlan"))) {
//                chosen = nif;
//            }
//        }
//
//// If still null, fallback to the first usable IPv4 adapter
//        if (chosen == null) {
//            for (PcapNetworkInterface nif : nifs) {
//                for (PcapAddress addr : nif.getAddresses()) {
//                    if (addr.getAddress() instanceof Inet4Address) {
//                        chosen = nif;
//                        break;
//                    }
//                }
//                if (chosen != null) break;
//            }
//        }
//
//        if (chosen == null) {
//            throw new IllegalStateException("No usable IPv4 adapter found.");
//        }
//
//        System.out.println("Auto-selected interface -> " + chosen.getName() + " / " + chosen.getDescription());
//        return chosen;
//
//    }
//
//
//    private void sendTcpSyn(PcapHandle handle, PcapNetworkInterface nif,
//                            InetAddress dst, int dstPort) throws Exception {
//
//        // Source IPv4 from selected interface
//        Inet4Address srcAddr = null;
//        for (PcapAddress addr : nif.getAddresses()) {
//            if (addr.getAddress() instanceof Inet4Address) {
//                srcAddr = (Inet4Address) addr.getAddress();
//                break;
//            }
//        }
//        if (srcAddr == null) {
//            throw new IllegalStateException("No IPv4 address for interface " + nif.getName());
//        }
//
//        // Source MAC
//        if (nif.getLinkLayerAddresses() == null || nif.getLinkLayerAddresses().isEmpty()) {
//            throw new IllegalStateException("No link-layer (MAC) address found for " + nif.getName());
//        }
//        MacAddress srcMac = (MacAddress) nif.getLinkLayerAddresses().get(0);
//
//        // Destination MAC via your resolver
//        com.smartnet.smartnet.network.macutils.Mac macResolver =
//                new com.smartnet.smartnet.network.macutils.Mac();
//        String dstMacStr = macResolver.resolveMac(dst.getHostAddress());
//        MacAddress dstMac = null;
//        if (dstMacStr != null && !"Unknown".equalsIgnoreCase(dstMacStr)) {
//            dstMac = toMacAddress(dstMacStr);
//        }
//        if (dstMac == null) {
//            // fallback to broadcast if ARP failed (still lets the frame out on L2)
//            dstMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
//        }
//
//        // TCP builder — include pseudo-header IPs for checksum
//        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
//        tcpBuilder
//                .srcPort(new TcpPort((short) ThreadLocalRandom.current().nextInt(1025, 65535), ""))
//                .dstPort(new TcpPort((short) dstPort, ""))
//                .syn(true)
//                .window((short) 64240)
//                .sequenceNumber(ThreadLocalRandom.current().nextInt())
//                .correctChecksumAtBuild(true)
//                .correctLengthAtBuild(true)
//                // ⬇️ These are crucial; without them you get builder.srcAddr/dstAddr null
//                .srcAddr(srcAddr)
//                .dstAddr((Inet4Address) dst);
//
//        // IPv4 builder
//        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
//        ipBuilder
//                .version(IpVersion.IPV4)
//                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
//                .ttl((byte) 64)
//                .protocol(IpNumber.TCP)
//                .srcAddr(srcAddr)
//                .dstAddr((Inet4Address) dst)
//                .payloadBuilder(tcpBuilder)
//                .correctChecksumAtBuild(true)
//                .correctLengthAtBuild(true);
//
//        // Ethernet frame
//        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
//        etherBuilder
//                .dstAddr(dstMac)
//                .srcAddr(srcMac)
//                .type(EtherType.IPV4)
//                .payloadBuilder(ipBuilder)
//                .paddingAtBuild(true);
//
//        handle.sendPacket(etherBuilder.build());
//    }
//
//    /** Normalize various MAC formats into something MacAddress can parse. */
//    private MacAddress toMacAddress(String raw) {
//        if (raw == null) return null;
//        String s = raw.trim().toLowerCase();
//        // Convert Windows "aa-bb-cc-dd-ee-ff" to "aa:bb:cc:dd:ee:ff"
//        if (s.contains("-")) s = s.replace('-', ':');
//        // Basic length sanity check: "aa:bb:cc:dd:ee:ff" => 17 chars
//        try {
//            return MacAddress.getByName(s);
//        } catch (IllegalArgumentException e) {
//            return null;
//        }
//    }
//}
//
////package com.smartnet.smartnet.network.osfingerprinting;
////
////import org.pcap4j.core.*;
////import org.pcap4j.packet.*;
////import org.pcap4j.packet.namednumber.*;
////import org.pcap4j.util.MacAddress;
////import com.smartnet.smartnet.network.osfingerprinting.OSFingerprintResult.OSFamily;
////import java.net.Inet4Address;
////import java.net.InetAddress;
////import java.util.*;
////import java.util.concurrent.ThreadLocalRandom;
////import java.util.concurrent.TimeoutException;
////
////public class OSFingerprintService {
////
////    public static class Config {
////        public List<Integer> probePorts = Arrays.asList(80, 443, 22);
////        public int readTimeoutMillis = 1500;
////        public int snapLen = 65536;
////        public int waitPerTargetMillis = 2000;
////        public boolean verbose = false;
////        public boolean usePromiscuous = false; // 🔧 default NONPROMISCUOUS
////        public InetAddress preferredSrcAddress = null;
////    }
////
////    private final Config cfg;
////
////    public OSFingerprintService() { this.cfg = new Config(); }
////    public OSFingerprintService(Config cfg) { this.cfg = cfg; }
////
////    public OSFingerprintResult fingerprint(String targetIp) throws Exception {
////        InetAddress dst = InetAddress.getByName(targetIp);
////        PcapNetworkInterface nif = chooseInterfaceForTarget(dst, cfg.preferredSrcAddress);
////
////        if (nif == null) {
////            throw new IllegalStateException("No suitable network interface found for " + targetIp);
////        }
////
////        if (cfg.verbose) {
////            System.out.println("Using interface: " + nif.getName() + " / " + nif.getDescription());
////        }
////
////        PcapNetworkInterface.PromiscuousMode mode =
////                cfg.usePromiscuous
////                        ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
////                        : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
////
////        PcapHandle handle = nif.openLive(cfg.snapLen, mode, cfg.readTimeoutMillis);
////        String bpf = "ip and (tcp or icmp) and host " + targetIp;
////        handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
////
////        // Send probes
////        for (int port : cfg.probePorts) {
////            sendTcpSyn(handle, nif, dst, port);
////        }
////
////        long end = System.currentTimeMillis() + cfg.waitPerTargetMillis;
////
////        Integer ttl = null;
////        Integer windowSize = null;
////        String tcpOptions = null;
////
////        while (System.currentTimeMillis() < end) {
////            try {
////                Packet packet = handle.getNextPacketEx();
////                if (packet.contains(IpV4Packet.class)) {
////                    IpV4Packet ip = packet.get(IpV4Packet.class);
////                    ttl = (int) ip.getHeader().getTtlAsInt();
////
////                    if (packet.contains(TcpPacket.class)) {
////                        TcpPacket tcp = packet.get(TcpPacket.class);
////                        windowSize = tcp.getHeader().getWindowAsInt();
////                        tcpOptions = tcp.getHeader().getOptions().toString();
////                        break; // got what we need
////                    }
////                }
////            } catch (TimeoutException ignored) {}
////        }
////
////        handle.close();
////
////        // Apply heuristic
////        OSFamily osFamily = OSFamily.UNKNOWN;
////        String desc = "No strong match";
////        double conf = 0.3;
////
////        if (ttl != null && windowSize != null) {
////            if (ttl >= 120 && ttl <= 130) {
////                if (windowSize == 8192 || windowSize == 65535) {
////                    osFamily = OSFamily.WINDOWS;
////                    desc = "Typical Windows signature";
////                    conf = 0.8;
////                }
////            } else if (ttl >= 60 && ttl <= 70) {
////                if (windowSize == 5840 || windowSize == 29200 || windowSize == 64240) {
////                    osFamily = OSFamily.LINUX;
////                    desc = "Typical Linux signature";
////                    conf = 0.8;
////                }
////            } else if (ttl >= 250) {
////                osFamily = OSFamily.MACOS;
////                desc = "Typical macOS signature";
////                conf = 0.7;
////            }
////        }
////
////        return new OSFingerprintResult(targetIp, osFamily, desc, conf, ttl, windowSize, tcpOptions);
////    }
////
////    // --- Helpers ---
////
////    private PcapNetworkInterface chooseInterfaceForTarget(InetAddress dst, InetAddress preferred) throws Exception {
////        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
//////        for (PcapNetworkInterface nif : nifs) {
//////            for (PcapAddress addr : nif.getAddresses()) {
//////                if (addr.getAddress() instanceof Inet4Address) {
//////                    if (preferred == null || addr.getAddress().equals(preferred)) {
//////                        return nif;
//////                    }
//////                }
//////            }
//////        }
//////        return null;
////        PcapNetworkInterface nif=nifs.get(6);
////        return nif;
////    }
////    private void sendTcpSyn(PcapHandle handle, PcapNetworkInterface nif,
////                            InetAddress dst, int dstPort) throws Exception {
////
////        // Get source IP
////        InetAddress srcAddr = null;
////        for (PcapAddress addr : nif.getAddresses()) {
////            if (addr.getAddress() instanceof Inet4Address) {
////                srcAddr = addr.getAddress();
////                break;
////            }
////        }
////        if (srcAddr == null) {
////            throw new IllegalStateException("No IPv4 address for interface " + nif.getName());
////        }
////
////        // Get source MAC from NIC
////        MacAddress srcMac = (MacAddress) nif.getLinkLayerAddresses().get(0);
////
////        // Resolve destination MAC using your Mac resolver class
////        com.smartnet.smartnet.network.macutils.Mac macResolver = new com.smartnet.smartnet.network.macutils.Mac();
////        String dstMacStr = macResolver.resolveMac(dst.getHostAddress());
////
////        // If ARP resolution fails, fallback to broadcast
////        MacAddress dstMac;
////        if (dstMacStr != null && !"Unknown".equalsIgnoreCase(dstMacStr)) {
////            dstMac = MacAddress.getByName(dstMacStr);
////        } else {
////            dstMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
////        }
////
////        // Build TCP SYN
////        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
////        tcpBuilder
////                .srcPort(new TcpPort((short) ThreadLocalRandom.current().nextInt(1025, 65535), ""))
////                .dstPort(new TcpPort((short) dstPort, ""))
////                .syn(true)
////                .window((short) 64240)
////                .sequenceNumber(ThreadLocalRandom.current().nextInt())
////                .correctChecksumAtBuild(true)
////                .correctLengthAtBuild(true);
////
////        // Build IPv4
////        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
////        ipBuilder.version(IpVersion.IPV4)
////                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
////                .ttl((byte) 64)
////                .protocol(IpNumber.TCP)
////                .srcAddr((Inet4Address) srcAddr)
////                .dstAddr((Inet4Address) dst)
////                .payloadBuilder(tcpBuilder)
////                .correctChecksumAtBuild(true)
////                .correctLengthAtBuild(true);
////
////        // Build Ethernet
////        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
////        etherBuilder.dstAddr(dstMac)
////                .srcAddr(srcMac)
////                .type(EtherType.IPV4)
////                .payloadBuilder(ipBuilder)
////                .paddingAtBuild(true);
////
////        // Send the packet
////        handle.sendPacket(etherBuilder.build());
////    }
////
////
//////    private void sendTcpSyn(PcapHandle handle, PcapNetworkInterface nif,
//////                            InetAddress dst, int dstPort) throws Exception {
//////
//////        InetAddress srcAddr = null;
//////        for (PcapAddress addr : nif.getAddresses()) {
//////            if (addr.getAddress() instanceof Inet4Address) {
//////                srcAddr = addr.getAddress();
//////                break;
//////            }
//////        }
//////        if (srcAddr == null) throw new IllegalStateException("No IPv4 address for interface " + nif.getName());
//////
//////        MacAddress srcMac = (MacAddress) nif.getLinkLayerAddresses().get(0);
//////        MacAddress dstMac = MacAddress.getByAddress(dst.getAddress()); // fallback (broadcast)
//////
//////        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
//////        tcpBuilder
//////                .srcPort(new TcpPort((short) ThreadLocalRandom.current().nextInt(1025, 65535), ""))
//////                .dstPort(new TcpPort((short) dstPort, ""))
//////                .syn(true).window((short) 64240)
//////                .sequenceNumber(ThreadLocalRandom.current().nextInt())
//////                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
//////
//////        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
//////        ipBuilder.version(IpVersion.IPV4)
//////                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
//////                .ttl((byte) 64)
//////                .protocol(IpNumber.TCP)
//////                .srcAddr((Inet4Address) srcAddr)
//////                .dstAddr((Inet4Address) dst)
//////                .payloadBuilder(tcpBuilder)
//////                .correctChecksumAtBuild(true)
//////                .correctLengthAtBuild(true);
//////
//////        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
//////        etherBuilder.dstAddr(dstMac)
//////                .srcAddr(srcMac)
//////                .type(EtherType.IPV4)
//////                .payloadBuilder(ipBuilder)
//////                .paddingAtBuild(true);
//////
//////        handle.sendPacket(etherBuilder.build());
//////    }
////}