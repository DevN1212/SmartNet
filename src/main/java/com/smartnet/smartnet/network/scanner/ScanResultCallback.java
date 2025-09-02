package com.smartnet.smartnet.network.scanner;

import com.smartnet.smartnet.network.models.HostScanResults;

public interface ScanResultCallback {
    void onResult(HostScanResults result);
}
