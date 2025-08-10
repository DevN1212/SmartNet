package com.smartnet.smartnet.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * NetworkScanner provides utilities to scan hosts and subnets for reachability and open ports.
 */
public class NetworkScanner {

    /**
     * Represents the result of scanning a single host.
     */
    public static class HostScanResults {
        public final String ipAddress;
        public final boolean isReachable;
        public final List<Integer> openPorts;
        public final String macAddress;
        public HostScanResults(String ipAddress, boolean isReachable, List<Integer> openPorts, String macAddress) {
            this.ipAddress = ipAddress;
            this.isReachable = isReachable;
            this.openPorts = openPorts;
            this.macAddress = macAddress;
        }
    }

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

    /**
     * Checks if a specific port is open on a host.
     */
    public boolean isPortOpen(String ipAddress, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ipAddress, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Scans a single host for reachability and open ports.
     */
    public HostScanResults scanHost(String ip, List<Integer> ports) {
        boolean isUP = isReachable(ip);
        List<Integer> openPorts = new ArrayList<>();
        String macAddress="-";
        if (isUP) {
            for (int port : ports) {
                if (isPortOpen(ip, port, 200)) {
                    openPorts.add(port);
                }
            }
            macAddress=resolveMac(ip);

        }

        return new HostScanResults(ip, isUP, openPorts,macAddress);
    }

    private String resolveMac(String ipAddress) {
        String os=System.getProperty("os.name").toLowerCase();
        try{
            if (os.contains("win")) {
                Runtime.getRuntime().exec("ping -n 1" + ipAddress).waitFor();
            }else{
                Runtime.getRuntime().exec("ping -c 1"+ipAddress);
            }

            ProcessBuilder pb;
            if(os.contains("win")){
                pb=new ProcessBuilder("arp","-a",ipAddress);
            } else if (os.contains("nix")|| os.contains("nux")) {
                pb=new ProcessBuilder("arp","-n",ipAddress);
            } else if (os.contains("mac")) {
                pb=new ProcessBuilder("arp",ipAddress);
            }else {
                return "OS not Supported";
            }

            Process process=pb.start();
            try(BufferedReader reader=new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line=reader.readLine())!=null){
                    String macAddress=getMac(line,os);
                    if(macAddress!=null){
                        return macAddress;
                    }
                }
            }


        }catch (Exception e){
            e.printStackTrace();
        }
        return "Unknown";
    }

    private String getMac(String line,String os) {
        line=line.trim();
        String macRegexWindows = "([0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5})";
        String macRegexUnix = "([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})";
        if (os.contains("win") && line.matches(".*" + macRegexWindows + ".*")) {
            return line.replaceAll(".*" + macRegexWindows + ".*", "$1");
        } else if ((os.contains("nix") || os.contains("nux") || os.contains("mac")) &&
                line.matches(".*" + macRegexUnix + ".*")) {
            return line.replaceAll(".*" + macRegexUnix + ".*", "$1");
        }
        return null;
    }

    /**
     * Scans a subnet using a thread pool for concurrency.
     */
    public List<HostScanResults> scanSubnetCIDRThreadPool(String cidr, List<Integer> ports, int threads) {
        List<String> ipAddresses = generateIP(cidr);
        threads=Math.min(threads, ipAddresses.size());
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<HostScanResults>> futures = new ArrayList<>();

        for (String ip : ipAddresses) {
            futures.add(executor.submit(() -> scanHost(ip, ports)));
        }

        List<HostScanResults> results = new ArrayList<>();
        for (Future<HostScanResults> future : futures) {
            try {
                results.add(future.get());
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }

        executor.shutdown();
        return results;
    }

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


    // Uncomment for testing
    // public static void main(String[] args) {
    //     List<String> ips = new NetworkScanner().generateIP("192.168.1.5/25");
    //     for (String ip : ips) {
    //         System.out.println(ip);
    //     }
    // }
}
