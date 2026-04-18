package com.example.riskcalculator.domain.model;

import com.example.riskcalculator.domain.enums.ConfidenceNeed;
import com.example.riskcalculator.domain.enums.FreshnessLevel;
import com.example.riskcalculator.domain.enums.RetrievalIntent;

/**
 * The cognitive profile derived from the assessment request.
 * Drives how retrieval should be planned and executed.
 */
public record ContextProfile(
        RetrievalIntent retrievalIntent,
        FreshnessLevel freshnessRequired,
        boolean explainabilityRequired,
        ConfidenceNeed confidenceNeed
) {}
