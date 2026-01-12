package com.tuorg.apigate.web.dto;

import jakarta.validation.constraints.NotBlank;

public record DemoRequest(
    @NotBlank String accountId,
    @NotBlank String type // "ONLINE" o "BATCH"
) {}
