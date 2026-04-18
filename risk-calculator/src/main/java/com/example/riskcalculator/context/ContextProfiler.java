package com.example.riskcalculator.context;

import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;

/**
 * Derives a {@link ContextProfile} from an incoming assessment request.
 * Implementations apply domain rules to infer retrieval intent,
 * freshness requirements, and explainability needs.
 */
public interface ContextProfiler {

    ContextProfile profile(RiskAssessmentRequest request);
}
