package com.securechat.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class ClientResourceTest {

    @Test
    @DisplayName("Verify JavaFX FXML and CSS resources exist on classpath")
    void testResourcesExist() {
        URL fxmlUrl = getClass().getResource("/view/splash.fxml");
        URL cssUrl = getClass().getResource("/css/style.css");

        assertNotNull(fxmlUrl, "splash.fxml must be present on the classpath");
        assertNotNull(cssUrl, "style.css must be present on the classpath");
    }

    @Test
    @DisplayName("Verify Bouncy Castle Security Provider Registration")
    void testSecurityProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        assertNotNull(Security.getProvider("BC"), "Bouncy Castle provider should be registered");
    }
}
