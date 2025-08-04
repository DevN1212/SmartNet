module com.smartnet.smartnet {
    requires javafx.controls;
    requires javafx.fxml;
        requires javafx.web;
            
        requires org.controlsfx.controls;
                    requires org.kordamp.ikonli.javafx;
            requires org.kordamp.bootstrapfx.core;
            requires eu.hansolo.tilesfx;
        
    opens com.smartnet.smartnet to javafx.fxml;
    exports com.smartnet.smartnet;
}