package com.example.riskcalculator.context;

import com.example.riskcalculator.domain.enums.ConfidenceNeed;
import com.example.riskcalculator.domain.enums.FreshnessLevel;
import com.example.riskcalculator.domain.enums.RetrievalIntent;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultContextProfilerTest {

    private DefaultContextProfiler profiler;

    @BeforeEach
    void setUp() {
        profiler = new DefaultContextProfiler();
    }

    private RiskAssessmentRequest buildRequest(String assessmentType, String criticality, List<String> signals) {
        return new RiskAssessmentRequest(
                "A-001", "REPOSITORY", "payments-api",
                "OPERATIONAL", criticality, assessmentType,
                signals, "JAVA", List.of("api"), 90
        );
    }

    @Test
    @DisplayName("INITIAL assessment type maps to BASELINE_RISK_DISCOVERY")
    void initial_assessmentType_mapsToBaselineIntent() {
        RiskAssessmentRequest request = buildRequest("INITIAL", "LOW", List.of());
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.retrievalIntent()).isEqualTo(RetrievalIntent.BASELINE_RISK_DISCOVERY);
    }

    @Test
    @DisplayName("RECALCULATION with high-freshness signals produces correct profile")
    void recalculation_withHighFreshnessSignals_producesCorrectProfile() {
        RiskAssessmentRequest request = buildRequest(
                "RECALCULATION", "HIGH",
                List.of("availability_findings", "control_evidence_expired")
        );
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.retrievalIntent()).isEqualTo(RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE);
        assertThat(profile.freshnessRequired()).isEqualTo(FreshnessLevel.HIGH);
        assertThat(profile.explainabilityRequired()).isTrue();
        assertThat(profile.confidenceNeed()).isEqualTo(ConfidenceNeed.HIGH);
    }

    @Test
    @DisplayName("AUDIT assessment type maps to EXACT_CONTROL_EVIDENCE")
    void audit_assessmentType_mapsToExactControlEvidence() {
        RiskAssessmentRequest request = buildRequest("AUDIT", "MEDIUM", List.of());
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.retrievalIntent()).isEqualTo(RetrievalIntent.EXACT_CONTROL_EVIDENCE);
    }

    @Test
    @DisplayName("LOW criticality does not require explainability")
    void lowCriticality_doesNotRequireExplainability() {
        RiskAssessmentRequest request = buildRequest("INITIAL", "LOW", List.of());
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.explainabilityRequired()).isFalse();
    }

    @Test
    @DisplayName("No high-freshness signals defaults to MEDIUM freshness")
    void noHighFreshnessSignals_defaultsToMediumFreshness() {
        RiskAssessmentRequest request = buildRequest("INITIAL", "LOW", List.of("some_other_signal"));
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.freshnessRequired()).isEqualTo(FreshnessLevel.MEDIUM);
    }

    @Test
    @DisplayName("confidenceNeed is always HIGH")
    void confidenceNeed_isAlwaysHigh() {
        RiskAssessmentRequest request = buildRequest("INITIAL", "LOW", List.of());
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.confidenceNeed()).isEqualTo(ConfidenceNeed.HIGH);
    }

    @Test
    @DisplayName("Unknown assessmentType defaults to BASELINE_RISK_DISCOVERY")
    void unknownAssessmentType_defaultsToBaseline() {
        RiskAssessmentRequest request = buildRequest("UNKNOWN_TYPE", "LOW", List.of());
        ContextProfile profile = profiler.profile(request);

        assertThat(profile.retrievalIntent()).isEqualTo(RetrievalIntent.BASELINE_RISK_DISCOVERY);
    }
}
