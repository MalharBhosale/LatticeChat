package com.securechat.common.dto;

import java.util.List;

/**
 * Request DTO for replenishing a user's pool of one-time prekeys.
 */
public record UploadPrekeysRequest(
        List<OneTimePrekeyUploadDto> prekeys
) {}
