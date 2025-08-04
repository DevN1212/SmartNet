package com.smartnet.smartnet;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import com.smartnet.smartnet.network.NetworkScanner;

import java.util.Arrays;
import java.util.List;

public class SmartNetController {

    @FXML
    private TextField cidrAddress;

    @FXML
    private Button scan;

    @FXML
    private TableView<NetworkScanner.HostScanResults> resultTable;

    @FXML
    private TableColumn<NetworkScanner.HostScanResults, String> ipColumn;

    @FXML
    private TableColumn<NetworkScanner.HostScanResults, String> statusColumn;

    @FXML
    private TableColumn<NetworkScanner.HostScanResults, String> portsColumn;

    @FXML
    private VBox loadingOverlay;  // Spinner container

    private final NetworkScanner scanner = new NetworkScanner();
    private final ObservableList<NetworkScanner.HostScanResults> scanResults = FXCollections.observableArrayList();

    @FXML
    public void initialize() {
        ipColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().ipAddress));
        statusColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().isReachable ? "UP" : "DOWN"));
        portsColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(
                        data.getValue().openPorts.isEmpty() ? "-" : data.getValue().openPorts.toString()));

        resultTable.setItems(scanResults);
    }

    @FXML
    protected void startScan() {
        String cidr = cidrAddress.getText().trim();
        scanResults.clear();

        if (!cidr.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}\\b")) {
            showAlert("Invalid CIDR format. Example: 192.168.1.0/24");
            return;
        }

        scan.setDisable(true);
        loadingOverlay.setVisible(true);
        resultTable.setVisible(false);

        new Thread(() -> {
            List<Integer> ports = Arrays.asList(22, 80, 443, 8080);
            List<NetworkScanner.HostScanResults> results = scanner.scanSubnetCIDRThreadPool(cidr, ports, 10);

            Platform.runLater(() -> {
                for (NetworkScanner.HostScanResults result : results) {
                    if (result.isReachable) {
                        scanResults.add(result);
                    }
                }
                scan.setDisable(false);
                loadingOverlay.setVisible(false);
                resultTable.setVisible(true);
            });
        }).start();
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Input Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
