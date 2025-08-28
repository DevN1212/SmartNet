package com.smartnet.smartnet.network.dnsutils;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class DnsResolver {
    public String resolveReverseDns(String ipAddress){
        try {
            InetAddress inetAddress=InetAddress.getByName(ipAddress);
            String hostName=inetAddress.getCanonicalHostName();
            if(!hostName.equals(ipAddress)){
                return hostName;
            }else {
                return "N/A";
            }
        } catch (UnknownHostException e) {
            return "N/A";
        }
    }
}
