package com.example.riskcalculator.context;

import com.example.riskcalculator.domain.enums.ConfidenceNeed;
import com.example.riskcalculator.domain.enums.FreshnessLevel;
import com.example.riskcalculator.domain.enums.RetrievalIntent;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Default rule-based implementation of {@link ContextProfiler}.
 *
 * <p>Rules:
 * <ul>
 *   <li>assessmentType = INITIAL  → BASELINE_RISK_DISCOVERY</li>
 *   <li>assessmentType = RECALCULATION → RECENT_OPERATIONAL_EVIDENCE</li>
 *   <li>assessmentType = AUDIT → EXACT_CONTROL_EVIDENCE</li>
 *   <li>criticality = HIGH → explainabilityRequired = true</li>
 *   <li>signals contain availability_findings or control_evidence_expired → freshness HIGH</li>
 *   <li>default freshness = MEDIUM</li>
 *   <li>confidenceNeed always HIGH</li>
 * </ul>
 */
@Component
public class DefaultContextProfiler implements ContextProfiler {

    private static final List<String> HIGH_FRESHNESS_SIGNALS =
            List.of("availability_findings", "control_evidence_expired");

    @Override
    public ContextProfile profile(RiskAssessmentRequest request) {
        RetrievalIntent intent = resolveIntent(request.assessmentType());
        boolean explainability = "HIGH".equalsIgnoreCase(request.criticality());
        FreshnessLevel freshness = resolveFreshness(request.signals());

        return new ContextProfile(intent, freshness, explainability, ConfidenceNeed.HIGH);
    }

    private RetrievalIntent resolveIntent(String assessmentType) {
        if (assessmentType == null) {
            return RetrievalIntent.BASELINE_RISK_DISCOVERY;
        }
        return switch (assessmentType.toUpperCase()) {
            case "INITIAL"        -> RetrievalIntent.BASELINE_RISK_DISCOVERY;
            case "RECALCULATION"  -> RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE;
            case "AUDIT"          -> RetrievalIntent.EXACT_CONTROL_EVIDENCE;
            default               -> RetrievalIntent.BASELINE_RISK_DISCOVERY;
        };
    }

    private FreshnessLevel resolveFreshness(List<String> signals) {
        if (signals == null || signals.isEmpty()) {
            return FreshnessLevel.MEDIUM;
        }
        boolean hasHighFreshnessSignal = signals.stream()
                .anyMatch(HIGH_FRESHNESS_SIGNALS::contains);
        return hasHighFreshnessSignal ? FreshnessLevel.HIGH : FreshnessLevel.MEDIUM;
    }
}
