package com.securechat.server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class SecureChatServerApplication {

    private static final Logger log = LoggerFactory.getLogger(SecureChatServerApplication.class);

    public static void main(String[] args) {
        // Register Bouncy Castle provider (houses both classical and Post-Quantum cryptography)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            log.info("Registered Bouncy Castle Security Provider");
        }

        SpringApplication.run(SecureChatServerApplication.class, args);
    }
}
