package com.smartnet.smartnet.network.macutils;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Mac {
    public String resolveMac(String ipAddress) {
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
}
