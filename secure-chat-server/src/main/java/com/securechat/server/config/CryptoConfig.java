package com.securechat.server.config;

import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration declaring Post-Quantum Cryptographic services (NIST FIPS 203 & 204)
 * as injectable beans for server-side signature validation and key exchange support.
 */
@Configuration
public class CryptoConfig {

    @Bean
    public SignatureService signatureService() {
        return new MlDsaSignatureService();
    }

    @Bean
    public KeyExchangeService keyExchangeService() {
        return new MlKemKeyExchangeService();
    }
}
