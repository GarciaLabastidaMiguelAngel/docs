package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;

/**
 * Builds a {@link RetrievalPlan} from a request and its derived context profile.
 * Each implementation may apply different planning heuristics.
 */
public interface RetrievalStrategyPlanner {

    RetrievalPlan plan(RiskAssessmentRequest request, ContextProfile contextProfile);
}
