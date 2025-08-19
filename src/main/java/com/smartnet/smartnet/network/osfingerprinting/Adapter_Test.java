package com.smartnet.smartnet.network.osfingerprinting;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import java.util.List;
public class Adapter_Test {
    public static void main(String[] args) {
        List<PcapNetworkInterface> allDevs= null;
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
        for (int i=0;i<allDevs.size();i++){
            System.out.println(i+":"+allDevs.get(i).getName()+"/"+allDevs.get(i).getDescription());
        }

    }
}
