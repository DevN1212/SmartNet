package com.smartnet.smartnet;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import com.smartnet.smartnet.network.scanner.NetworkScanner;
import com.smartnet.smartnet.network.models.HostScanResults;

import java.util.Arrays;
import java.util.List;

public class SmartNetController {

    @FXML
    private TextField IPAddress_in;
    @FXML
    private TextField cidrRange;
    @FXML
    private Button scan;

    @FXML
    private ToggleGroup portOptionGroup;

    @FXML
    private RadioButton popularPortsRadio;
    @FXML
    private RadioButton top1000PortsRadio;
    @FXML
    private RadioButton customPortsRadio;

    @FXML
    private TextField customPortsField;
    @FXML
    private TableView<HostScanResults> resultTable;

    @FXML
    private TableColumn<HostScanResults, String> ipColumn;
    @FXML
    private TableColumn<HostScanResults,String> macColumn;
    @FXML
    private TableColumn<HostScanResults,String> hostColumn;
    @FXML
    private TableColumn<HostScanResults, String> statusColumn;

    @FXML
    private TableColumn<HostScanResults, String> portsColumn;

    @FXML
    private VBox loadingOverlay;  // Spinner container

    private final NetworkScanner scanner = new NetworkScanner();
    private final ObservableList<HostScanResults> scanResults = FXCollections.observableArrayList();

    @FXML
    public void initialize() {
        ipColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().ipAddress));
        statusColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().isReachable ? "UP" : "DOWN"));
        portsColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(
                        data.getValue().openPorts.isEmpty() ? "-" : data.getValue().openPorts.toString()));
        macColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().macAddress));
        hostColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().hostName));
        popularPortsRadio.setToggleGroup(portOptionGroup);
        top1000PortsRadio.setToggleGroup(portOptionGroup);
        customPortsRadio.setToggleGroup(portOptionGroup);

        // Enable/disable custom port field based on selection
        customPortsRadio.selectedProperty().addListener((obs, oldVal, newVal) -> {
            customPortsField.setDisable(!newVal);
        });

        resultTable.setItems(scanResults);
    }
    @FXML
    protected void startScan() {
        String IPAddress = IPAddress_in.getText().trim();
        scanResults.clear();

        // Validate base IP
        String ipRegex = "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$";
        if (!IPAddress.matches(ipRegex)) {
            showAlert("Invalid IP Address");
            return;
        }

        String prefix = cidrRange.getText().trim(); // e.g. "/24"
        boolean isCIDR;
        String fullCIDR;

        // Validate prefix and form CIDR if valid
        if (!prefix.isEmpty()) {
            if (prefix.matches("^/(\\d|[12]\\d|3[0-2])$")) {
                isCIDR = true;
                fullCIDR = IPAddress + prefix;
            } else {
                fullCIDR = "";
                isCIDR = false;
                showAlert("Invalid CIDR prefix (e.g., /24)");
                return;
            }
        } else {
            fullCIDR = "";
            isCIDR = false;
        }

        // UI preparation
        scan.setDisable(true);
        loadingOverlay.setVisible(true);
        resultTable.setVisible(false);

        new Thread(() -> {
            List<Integer> ports;

            if (popularPortsRadio.isSelected()) {
                ports = Arrays.asList(22, 80, 443, 8080, 21, 23, 25, 110); // Add more if needed
            } else if (top1000PortsRadio.isSelected()) {
                ports = new java.util.ArrayList<>();
                for (int i = 1; i <= 1000; i++) {
                    ports.add(i);
                }
            } else {
                // Custom ports
                ports = new java.util.ArrayList<>();
                String customInput = customPortsField.getText().trim();
                if (customInput.isEmpty()) {
                    showAlert("Please enter custom ports (comma-separated).");
                    return;
                }
                try {
                    String[] parts = customInput.split(",");
                    for (String part : parts) {
                        int port = Integer.parseInt(part.trim());
                        if (port < 1 || port > 65535) {
                            showAlert("Port number out of range: " + port);
                            return;
                        }
                        ports.add(port);
                    }
                } catch (NumberFormatException e) {
                    showAlert("Invalid port format. Use comma-separated numbers.");
                    return;
                }
            }


            if (isCIDR) {
                // CIDR subnet scan
                List<HostScanResults> results = scanner.scanSubnetCIDRThreadPool(fullCIDR, ports, 10);
                Platform.runLater(() -> {
                    for (HostScanResults result : results) {
                        if (result.isReachable) {
                            scanResults.add(result);
                        }
                    }
                    finishScan();
                });
            } else {
                // Single IP scan
                HostScanResults result = scanner.scanHost(IPAddress, ports);
                Platform.runLater(() -> {
                    if (result.isReachable) {
                        scanResults.add(result);
                    }
                    finishScan();
                });
            }
        }).start();
    }

    private void finishScan() {
        scan.setDisable(false);
        loadingOverlay.setVisible(false);
        resultTable.setVisible(true);
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Input Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
