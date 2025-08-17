package com.smartnet.smartnet.network.utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class PortScanner {
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
}
