package com.securechat.client;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Security;

public class SecureChatClientApp extends Application {

    @Override
    public void init() {
        // Register Bouncy Castle Security Provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/splash.fxml"));
        Scene scene = new Scene(loader.load(), 800, 600);

        primaryStage.setTitle("SecureChat — Post-Quantum Secure Messaging");
        primaryStage.setMinWidth(700);
        primaryStage.setMinHeight(500);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
