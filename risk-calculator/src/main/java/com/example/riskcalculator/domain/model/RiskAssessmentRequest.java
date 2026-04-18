package com.example.riskcalculator.domain.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.util.List;

/**
 * Incoming request to contextualize a risk assessment.
 * All fields are validated via Jakarta Validation.
 */
public record RiskAssessmentRequest(

        @NotBlank(message = "assessmentId is required")
        String assessmentId,

        @NotBlank(message = "assetType is required")
        String assetType,

        @NotBlank(message = "assetId is required")
        String assetId,

        @NotBlank(message = "domain is required")
        String domain,

        @NotBlank(message = "criticality is required")
        String criticality,

        @NotBlank(message = "assessmentType is required")
        String assessmentType,

        List<String> signals,

        @NotBlank(message = "technology is required")
        String technology,

        List<String> tags,

        @NotNull(message = "timeHorizonDays is required")
        @Positive(message = "timeHorizonDays must be positive")
        Integer timeHorizonDays
) {}
