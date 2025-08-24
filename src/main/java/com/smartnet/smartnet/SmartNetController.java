package com.smartnet.smartnet;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.layout.GridPane;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import com.smartnet.smartnet.network.scanner.NetworkScanner;
import com.smartnet.smartnet.network.models.HostScanResults;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class SmartNetController {

    @FXML private TextField IPAddress_in;
    @FXML private TextField cidrRange;
    @FXML private Button scan;

    @FXML private ToggleGroup portOptionGroup;
    @FXML private RadioButton popularPortsRadio;
    @FXML private RadioButton top1000PortsRadio;
    @FXML private RadioButton customPortsRadio;
    @FXML private CheckBox osScanCheckBox;
    @FXML private TextField customPortsField;

    @FXML private TableView<HostScanResults> resultTable;
    @FXML private TableColumn<HostScanResults, String> ipColumn;
    @FXML private TableColumn<HostScanResults,String> macColumn;
    @FXML private TableColumn<HostScanResults,String> hostColumn;
    @FXML private TableColumn<HostScanResults, String> statusColumn;
//    @FXML private TableColumn<HostScanResults, String> portsColumn;
    @FXML private TableColumn<HostScanResults, String> osColumn;

    @FXML private VBox loadingOverlay;  // Spinner container
    @FXML private Button exportCSV;

    // Details panel fields
    @FXML private Label detailIp;
    @FXML private Label detailMac;
    @FXML private Label detailHost;
    @FXML private Label detailOs;
    @FXML private Label detailPorts;

    private final NetworkScanner scanner = new NetworkScanner();
    private final ObservableList<HostScanResults> scanResults = FXCollections.observableArrayList();

    @FXML
    public void initialize() {
        ipColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().ipAddress));
        statusColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().isReachable ? "UP" : "DOWN"));
//        portsColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(
//                        data.getValue().openPorts.isEmpty() ? "-" : data.getValue().openPorts.toString()));
        macColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().macAddress));
        hostColumn.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().hostName));
        osColumn.setCellValueFactory(data->
                new javafx.beans.property.SimpleStringProperty(
                        data.getValue().osName !=null?data.getValue().osName :"Unknown"
                ));

        popularPortsRadio.setToggleGroup(portOptionGroup);
        top1000PortsRadio.setToggleGroup(portOptionGroup);
        customPortsRadio.setToggleGroup(portOptionGroup);

        // Enable/disable custom port field based on selection
        customPortsRadio.selectedProperty().addListener((obs, oldVal, newVal) -> {
            customPortsField.setDisable(!newVal);
        });

        osColumn.setVisible(false);
        osScanCheckBox.selectedProperty().addListener((obs, oldVal, newVal) -> {
            osColumn.setVisible(newVal);
        });

        resultTable.setColumnResizePolicy(TableView.UNCONSTRAINED_RESIZE_POLICY);
        resultTable.setItems(scanResults);
        exportCSV.setDisable(true);

        // 🔹 Update details panel when row is selected
        resultTable.getSelectionModel().selectedItemProperty().addListener(
                (obs, oldSel, newSel) -> {
                    if (newSel != null) {
                        detailIp.setText(newSel.getIpAddress());
                        detailMac.setText(newSel.getMacAddress());
                        detailHost.setText(newSel.getHostName());
                        detailOs.setText(newSel.getOsName() != null ? newSel.getOsName() : "Unknown");
                        detailPorts.setText(newSel.getOpenPorts().isEmpty() ? "-" :
                                String.join(", ", newSel.getOpenPorts().toString()));
                    } else {
                        detailIp.setText("-");
                        detailMac.setText("-");
                        detailHost.setText("-");
                        detailOs.setText("-");
                        detailPorts.setText("-");
                    }
                }
        );
    }

    @FXML
    protected void startScan() {
        exportCSV.setDisable(true);
        String IPAddress = IPAddress_in.getText().trim();
        scanResults.clear();

        String ipRegex = "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$";
        if (!IPAddress.matches(ipRegex)) {
            showAlert("Invalid IP Address");
            return;
        }

        String prefix = cidrRange.getText().trim();
        boolean isCIDR;
        String fullCIDR;

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

        scan.setDisable(true);
        loadingOverlay.setVisible(true);
        resultTable.setVisible(false);

        new Thread(() -> {
            List<Integer> ports;
            if (popularPortsRadio.isSelected()) {
                ports = Arrays.asList(22, 80, 443, 8080, 21, 23, 25, 110);
            } else if (top1000PortsRadio.isSelected()) {
                ports = new java.util.ArrayList<>();
                for (int i = 1; i <= 1000; i++) {
                    ports.add(i);
                }
            } else {
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

            boolean osScan = osScanCheckBox.isSelected();

            if (isCIDR) {
                List<HostScanResults> results = scanner.scanSubnetCIDRThreadPool(fullCIDR, ports, 10, osScan);
                Platform.runLater(() -> {
                    for (HostScanResults result : results) {
                        if (result.isReachable) {
                            scanResults.add(result);
                        }
                    }
                    finishScan();
                    if(!scanResults.isEmpty()) exportCSV.setDisable(false);
                });
            } else {
                HostScanResults result;
                try {
                    if(osScanCheckBox.isSelected()) result = scanner.scanHost(IPAddress, ports, osScan);
                    else result = scanner.scanHost(IPAddress, ports);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                Platform.runLater(() -> {
                    if (result.isReachable) {
                        scanResults.add(result);
                    }
                    finishScan();
                    if(!scanResults.isEmpty()) exportCSV.setDisable(false);
                });
            }
        }).start();
    }

    @FXML
    private void onExportCSV(){
        FileChooser fileChooser=new FileChooser();
        fileChooser.setTitle("Save CSV Report");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files","*.csv"));
        File file=fileChooser.showSaveDialog(resultTable.getScene().getWindow());
        if(file!=null){
            try(FileWriter writer=new FileWriter(file)) {
                if(osScanCheckBox.isSelected()) {
                    writer.write("IP,Hostname,MAC,Open_Ports,OS\n");
                    for (HostScanResults results:resultTable.getItems()){
                        writer.write(String.format("%s,%s,%s,%s,%s\n",
                                results.getIpAddress(),
                                results.getHostName(),
                                results.getMacAddress(),
                                results.getOpenPorts().toString(),
                                results.getOsName()
                        ));
                    }
                }
                else {
                    writer.write("IP,Hostname,MAC,Open_Ports\n");
                    for (HostScanResults results:resultTable.getItems()){
                        writer.write(String.format("%s,%s,%s,%s\n",
                                results.getIpAddress(),
                                results.getHostName(),
                                results.getMacAddress(),
                                results.getOpenPorts().toString()
                        ));
                    }
                }
            }catch (IOException e) {
                e.printStackTrace();
                new Alert(Alert.AlertType.ERROR, "Failed to export CSV: " + e.getMessage()).showAndWait();
            }
        }
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

//package com.smartnet.smartnet;
//
//import javafx.application.Platform;
//import javafx.fxml.FXML;
//import javafx.scene.control.*;
//import javafx.scene.layout.VBox;
//import javafx.collections.FXCollections;
//import javafx.collections.ObservableList;
//import com.smartnet.smartnet.network.scanner.NetworkScanner;
//import com.smartnet.smartnet.network.models.HostScanResults;
//import javafx.stage.FileChooser;
//
//import java.io.File;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.util.Arrays;
//import java.util.List;
//
//public class SmartNetController {
//
//    @FXML
//    private TextField IPAddress_in;
//    @FXML
//    private TextField cidrRange;
//    @FXML
//    private Button scan;
//
//    @FXML
//    private ToggleGroup portOptionGroup;
//
//    @FXML
//    private RadioButton popularPortsRadio;
//    @FXML
//    private RadioButton top1000PortsRadio;
//    @FXML
//    private RadioButton customPortsRadio;
//    @FXML
//    private CheckBox osScanCheckBox;
//    @FXML
//    private TextField customPortsField;
//    @FXML
//    private TableView<HostScanResults> resultTable;
//    @FXML
//    private TableColumn<HostScanResults, String> ipColumn;
//    @FXML
//    private TableColumn<HostScanResults,String> macColumn;
//    @FXML
//    private TableColumn<HostScanResults,String> hostColumn;
//    @FXML
//    private TableColumn<HostScanResults, String> statusColumn;
//
//    @FXML
//    private TableColumn<HostScanResults, String> portsColumn;
//    @FXML
//    private TableColumn<HostScanResults, String> osColumn;
//    @FXML
//    private VBox loadingOverlay;  // Spinner container
//    @FXML
//    private Button exportCSV;
//    private final NetworkScanner scanner = new NetworkScanner();
//    private final ObservableList<HostScanResults> scanResults = FXCollections.observableArrayList();
//
//    @FXML
//    public void initialize() {
//        ipColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(data.getValue().ipAddress));
//        statusColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(data.getValue().isReachable ? "UP" : "DOWN"));
//        portsColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(
//                        data.getValue().openPorts.isEmpty() ? "-" : data.getValue().openPorts.toString()));
//        macColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(data.getValue().macAddress));
//        hostColumn.setCellValueFactory(data ->
//                new javafx.beans.property.SimpleStringProperty(data.getValue().hostName));
//        osColumn.setCellValueFactory(data->
//                new javafx.beans.property.SimpleStringProperty(
//                        data.getValue().osName !=null?data.getValue().osName :"Unknown"
//                ));
//        popularPortsRadio.setToggleGroup(portOptionGroup);
//        top1000PortsRadio.setToggleGroup(portOptionGroup);
//        customPortsRadio.setToggleGroup(portOptionGroup);
//
//        // Enable/disable custom port field based on selection
//        customPortsRadio.selectedProperty().addListener((obs, oldVal, newVal) -> {
//            customPortsField.setDisable(!newVal);
//        });
//        osColumn.setVisible(false);
//
//        // Toggle visibility when checkbox is clicked
//        osScanCheckBox.selectedProperty().addListener((obs, oldVal, newVal) -> {
//            osColumn.setVisible(newVal);
//        });
//        resultTable.setColumnResizePolicy(TableView.UNCONSTRAINED_RESIZE_POLICY);
//        resultTable.setItems(scanResults);
//        exportCSV.setDisable(true);
//    }
//    @FXML
//    protected void startScan() {
//        exportCSV.setDisable(true);
//        String IPAddress = IPAddress_in.getText().trim();
//        scanResults.clear();
//
//        // Validate base IP
//        String ipRegex = "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$";
//        if (!IPAddress.matches(ipRegex)) {
//            showAlert("Invalid IP Address");
//            return;
//        }
//
//        String prefix = cidrRange.getText().trim(); // e.g. "/24"
//        boolean isCIDR;
//        String fullCIDR;
//
//        // Validate prefix and form CIDR if valid
//        if (!prefix.isEmpty()) {
//            if (prefix.matches("^/(\\d|[12]\\d|3[0-2])$")) {
//                isCIDR = true;
//                fullCIDR = IPAddress + prefix;
//            } else {
//                fullCIDR = "";
//                isCIDR = false;
//                showAlert("Invalid CIDR prefix (e.g., /24)");
//                return;
//            }
//        } else {
//            fullCIDR = "";
//            isCIDR = false;
//        }
//
//        // UI preparation
//        scan.setDisable(true);
//        loadingOverlay.setVisible(true);
//        resultTable.setVisible(false);
//
//        new Thread(() -> {
//            List<Integer> ports;
//
//            if (popularPortsRadio.isSelected()) {
//                ports = Arrays.asList(22, 80, 443, 8080, 21, 23, 25, 110); // Add more if needed
//            } else if (top1000PortsRadio.isSelected()) {
//                ports = new java.util.ArrayList<>();
//                for (int i = 1; i <= 1000; i++) {
//                    ports.add(i);
//                }
//            } else {
//                // Custom ports
//                ports = new java.util.ArrayList<>();
//                String customInput = customPortsField.getText().trim();
//                if (customInput.isEmpty()) {
//                    showAlert("Please enter custom ports (comma-separated).");
//                    return;
//                }
//                try {
//                    String[] parts = customInput.split(",");
//                    for (String part : parts) {
//                        int port = Integer.parseInt(part.trim());
//                        if (port < 1 || port > 65535) {
//                            showAlert("Port number out of range: " + port);
//                            return;
//                        }
//                        ports.add(port);
//                    }
//                } catch (NumberFormatException e) {
//                    showAlert("Invalid port format. Use comma-separated numbers.");
//                    return;
//                }
//            }
//            boolean osScan=osScanCheckBox.isSelected();
//
//            if (isCIDR) {
//                // CIDR subnet scan
//                List<HostScanResults> results = scanner.scanSubnetCIDRThreadPool(fullCIDR, ports, 10,osScan);
//                Platform.runLater(() -> {
//                    for (HostScanResults result : results) {
//                        if (result.isReachable) {
//                            scanResults.add(result);
//                        }
//                    }
//                    finishScan();
//                    if(!scanResults.isEmpty()) exportCSV.setDisable(false);
//                });
//            } else {
//                // Single IP scan
//                HostScanResults result;
//                try {
//                    result = scanner.scanHost(IPAddress, ports,osScan);
//                } catch (Exception e) {
//                    throw new RuntimeException(e);
//                }
//                Platform.runLater(() -> {
//                    if (result.isReachable) {
//                        scanResults.add(result);
//                    }
//                    finishScan();
//                    if(!scanResults.isEmpty()) exportCSV.setDisable(false);
//                });
//            }
//        }).start();
//    }
//    @FXML
//    private void onExportCSV(){
//        FileChooser fileChooser=new FileChooser();
//        fileChooser.setTitle("Save CSV Report");
//        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files","*.csv"));
//        File file=fileChooser.showSaveDialog(resultTable.getScene().getWindow());
//        if(file!=null){
//            try(FileWriter writer=new FileWriter(file)) {
//                if(osScanCheckBox.isSelected()) {
//                    writer.write("IP,Hostname,MAC,Open_Ports,OS\n");
//                    for (HostScanResults results:resultTable.getItems()){
//                        writer.write(String.format("%s,%s,%s,%s,%s\n",
//                                results.getIpAddress(),
//                                results.getHostName(),
//                                results.getMacAddress(),
//                                results.getOpenPorts().toString(),
//                                results.getOsName()
//                                ));
//                    }
//                }
//                else {
//                    writer.write("IP,Hostname,MAC,Open_Ports\n");
//                    for (HostScanResults results:resultTable.getItems()){
//                        writer.write(String.format("%s,%s,%s,%s\n",
//                                results.getIpAddress(),
//                                results.getHostName(),
//                                results.getMacAddress(),
//                                results.getOpenPorts().toString()
//                        ));
//                    }
//                }
//            }catch (IOException e) {
//                e.printStackTrace();
//                new Alert(Alert.AlertType.ERROR, "Failed to export CSV: " + e.getMessage()).showAndWait();
//            }
//        }
//    }
//
//    private void finishScan() {
//        scan.setDisable(false);
//        loadingOverlay.setVisible(false);
//        resultTable.setVisible(true);
//    }
//
//    private void showAlert(String message) {
//        Alert alert = new Alert(Alert.AlertType.ERROR);
//        alert.setTitle("Input Error");
//        alert.setHeaderText(null);
//        alert.setContentText(message);
//        alert.showAndWait();
//    }
//}
