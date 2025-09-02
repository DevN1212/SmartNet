package com.smartnet.smartnet.network.scanner;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Consumer;
import com.smartnet.smartnet.network.dnsutils.DnsResolver;
import com.smartnet.smartnet.network.ipgenerator.IPGenerator;
import com.smartnet.smartnet.network.macutils.Mac;
import com.smartnet.smartnet.network.models.HostScanResults;
import com.smartnet.smartnet.network.networkinterfacemanager.NetworkInterfaceManager;
import com.smartnet.smartnet.network.utils.PortScanner;
import com.smartnet.smartnet.network.utils.Reachability;
import com.smartnet.smartnet.network.osfingerprinting.*;

/**
 * NetworkScanner provides utilities to scan hosts and subnets for reachability and open ports.
 */
public class NetworkScanner {

    private final Reachability reachability = new Reachability();
    private final Mac macResolver = new Mac();
    private final PortScanner portScanner = new PortScanner();
    private final DnsResolver dnsResolver = new DnsResolver();

    /**
     * Scans a single host for reachability and open ports.
     */
    public HostScanResults scanHost(String ip, List<Integer> ports) {
        boolean isUP = reachability.isReachable(ip);
        List<Integer> openPorts = new ArrayList<>();
        String macAddress = "-";
        String hostName = "N/A";

        if (isUP) {
            for (int port : ports) {
                if (portScanner.isPortOpen(ip, port, 200)) {
                    openPorts.add(port);
                }
            }
            hostName = dnsResolver.resolveReverseDns(ip);
            macAddress = macResolver.resolveMac(ip);
        }

        return new HostScanResults(ip, isUP, openPorts, macAddress, hostName);
    }

    public HostScanResults scanHost(String ip, List<Integer> ports, boolean osScan) throws Exception {
        boolean isUP = reachability.isReachable(ip);
        List<Integer> openPorts = new ArrayList<>();
        String macAddress = "-";
        String hostName = "N/A";
        String os = "Unknown";

        if (isUP) {
            for (int port : ports) {
                if (portScanner.isPortOpen(ip, port, 200)) {
                    openPorts.add(port);
                }
            }
            hostName = dnsResolver.resolveReverseDns(ip);
            macAddress = macResolver.resolveMac(ip);

            if (osScan) {
                try {
                    OSFingerprintService.Config config = new OSFingerprintService.Config();
                    config.verbose = true;
                    config.usePromiscuous = false;
                    OSFingerprintService service = new OSFingerprintService(config);
                    OSFingerprintResult result = service.fingerprint(ip);
                    os = result.getOsName();
                } catch (Exception e) {
                    // OS scan failed, keep "Unknown"
                    System.err.println("OS scan failed for " + ip + ": " + e.getMessage());
                }
            }
        }

        return new HostScanResults(ip, isUP, openPorts, macAddress, hostName, os);
    }

    /**
     * Interface for scan completion callback
     */
    public interface ScanCompletionCallback {
        void onScanComplete();
    }

    /**
     * Scans a subnet using a thread pool for concurrency with live updates and completion callback.
     */
    public void scanSubnetCIDRWithLiveUpdates(String cidr, List<Integer> ports, int threads, boolean osScan,
                                              Consumer<HostScanResults> resultCallback, ScanCompletionCallback completionCallback) {
        IPGenerator generator = new IPGenerator();
        List<String> ipAddresses = generator.generateIP(cidr);

        // Remove host IP to avoid scanning self
        try {
            String hostIp = NetworkInterfaceManager.getDefaultInterfaceIp();
            ipAddresses.remove(hostIp);
        } catch (Exception e) {
            System.err.println("Could not determine host IP: " + e.getMessage());
        }

        if (ipAddresses.isEmpty()) {
            completionCallback.onScanComplete();
            return;
        }

        threads = Math.min(threads, ipAddresses.size());
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        // Submit all scan tasks
        for (String ip : ipAddresses) {
            executor.submit(() -> {
                try {
                    HostScanResults result;
                    if (osScan) {
                        result = scanHost(ip, ports, true);
                    } else {
                        result = scanHost(ip, ports);
                    }
                    // Immediately notify callback of completed scan
                    resultCallback.accept(result);
                } catch (Exception e) {
                    System.err.println("Error scanning " + ip + ": " + e.getMessage());
                    // Still call callback with a failed result
                    resultCallback.accept(new HostScanResults(ip, false, new ArrayList<>(), "-", "N/A", "Unknown"));
                }
            });
        }

        // Shutdown executor and wait for completion in background
        new Thread(() -> {
            executor.shutdown();
            try {
                executor.awaitTermination(30, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            } finally {
                completionCallback.onScanComplete();
            }
        }).start();
    }

    /**
     * Scans a subnet using a thread pool for concurrency with live updates (no completion callback).
     */
    public void scanSubnetCIDRWithLiveUpdates(String cidr, List<Integer> ports, int threads, boolean osScan, Consumer<HostScanResults> resultCallback) {
        scanSubnetCIDRWithLiveUpdates(cidr, ports, threads, osScan, resultCallback, () -> {
            // Empty completion callback
        });
    }
    public List<HostScanResults> scanSubnetCIDRThreadPool(String cidr, List<Integer> ports, int threads, boolean osScan) {
        IPGenerator generator = new IPGenerator();
        List<String> ipAddresses = generator.generateIP(cidr);
        threads = Math.min(threads, ipAddresses.size());
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<HostScanResults>> futures = new ArrayList<>();

        try {
            String hostIp = NetworkInterfaceManager.getDefaultInterfaceIp();
            ipAddresses.remove(hostIp);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        for (String ip : ipAddresses) {
            futures.add(executor.submit(() -> {
                if (osScan) {
                    try {
                        return scanHost(ip, ports, true);
                    } catch (Exception e) {
                        return new HostScanResults(ip, false, new ArrayList<>(), "-", "N/A", "Unknown");
                    }
                } else {
                    return scanHost(ip, ports);
                }
            }));
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

    // Uncomment for testing
    // public static void main(String[] args) {
    //     List<String> ips = new NetworkScanner().generateIP("192.168.1.5/25");
    //     for (String ip : ips) {
    //         System.out.println(ip);
    //     }
    // }
}