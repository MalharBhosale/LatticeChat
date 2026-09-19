package com.securechat.common.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

/**
 * Request DTO for replenishing a user's pool of one-time prekeys.
 */
public record UploadPrekeysRequest(
        @NotNull(message = "Prekeys list cannot be null")
        @NotEmpty(message = "Prekeys list cannot be empty")
        List<OneTimePrekeyUploadDto> prekeys
) {}
