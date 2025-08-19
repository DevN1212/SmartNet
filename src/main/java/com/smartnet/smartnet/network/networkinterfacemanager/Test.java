package com.smartnet.smartnet.network.networkinterfacemanager;

import org.pcap4j.core.PcapNetworkInterface;

public class Test {
    public static void main(String[] args) {
        try {
            PcapNetworkInterface nif=NetworkInterfaceManager.getDefaultInterface();
            System.out.println(nif.getName()+"/"+nif.getDescription());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
