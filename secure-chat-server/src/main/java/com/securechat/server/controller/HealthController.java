package com.securechat.server.controller;

import com.securechat.common.dto.ApiResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Security;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    @Value("${app.crypto.kem-algorithm:ML-KEM-768}")
    private String kemAlgorithm;

    @Value("${app.crypto.dsa-algorithm:ML-DSA-65}")
    private String dsaAlgorithm;

    @GetMapping
    public ApiResponse<Map<String, Object>> getHealth() {
        boolean hasBouncyCastle = Security.getProvider("BC") != null;

        Map<String, Object> healthInfo = Map.of(
                "status", "UP",
                "service", "SecureChat Backend Server",
                "version", "1.0.0-SNAPSHOT",
                "javaVersion", System.getProperty("java.version"),
                "kemAlgorithm", kemAlgorithm,
                "dsaAlgorithm", dsaAlgorithm,
                "securityProvidersLoaded", Map.of(
                        "BouncyCastle_BC", hasBouncyCastle
                )
        );

        return ApiResponse.ok("Server is healthy and operational", healthInfo);
    }
}
