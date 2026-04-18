package com.example.riskcalculator.domain.model;

/**
 * Final response returned to the caller after contextualisation.
 * The status will always be READY_FOR_RISK_SCORING in V1.
 */
public record ContextualizedAssessmentResponse(
        String assessmentId,
        ContextProfile contextProfile,
        RetrievalPlan retrievalPlan,
        EvidenceBundle evidenceBundle,
        String status
) {}
