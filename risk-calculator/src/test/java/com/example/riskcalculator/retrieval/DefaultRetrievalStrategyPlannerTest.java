package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.enums.ConfidenceNeed;
import com.example.riskcalculator.domain.enums.FreshnessLevel;
import com.example.riskcalculator.domain.enums.RetrievalIntent;
import com.example.riskcalculator.domain.enums.RetrievalMode;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalStep;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultRetrievalStrategyPlannerTest {

    private DefaultRetrievalStrategyPlanner planner;

    @BeforeEach
    void setUp() {
        planner = new DefaultRetrievalStrategyPlanner();
    }

    private RiskAssessmentRequest buildRequest(String assessmentType) {
        return new RiskAssessmentRequest(
                "A-001", "REPOSITORY", "payments-api",
                "OPERATIONAL", "HIGH", assessmentType,
                List.of(), "JAVA", List.of("api"), 90
        );
    }

    private ContextProfile buildProfile(RetrievalIntent intent) {
        return new ContextProfile(intent, FreshnessLevel.HIGH, true, ConfidenceNeed.HIGH);
    }

    @Test
    @DisplayName("Plan always includes an EXACT step on asset_index")
    void plan_alwaysIncludesExactStepOnAssetIndex() {
        RetrievalPlan plan = planner.plan(
                buildRequest("INITIAL"),
                buildProfile(RetrievalIntent.BASELINE_RISK_DISCOVERY)
        );

        assertThat(plan.steps())
                .anyMatch(s -> s.mode() == RetrievalMode.EXACT && "asset_index".equals(s.index()));
    }

    @Test
    @DisplayName("Plan includes HYBRID step when intent is RECENT_OPERATIONAL_EVIDENCE")
    void plan_includesHybridStep_whenRecentOperationalEvidence() {
        RetrievalPlan plan = planner.plan(
                buildRequest("RECALCULATION"),
                buildProfile(RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE)
        );

        List<RetrievalStep> hybridSteps = plan.steps().stream()
                .filter(s -> s.mode() == RetrievalMode.HYBRID)
                .toList();

        assertThat(hybridSteps).hasSize(1);
        assertThat(hybridSteps.get(0).index()).isEqualTo("finding_index");
        assertThat(hybridSteps.get(0).topK()).isEqualTo(10);
    }

    @Test
    @DisplayName("Plan does NOT include HYBRID step for BASELINE_RISK_DISCOVERY intent")
    void plan_excludesHybridStep_forBaselineIntent() {
        RetrievalPlan plan = planner.plan(
                buildRequest("INITIAL"),
                buildProfile(RetrievalIntent.BASELINE_RISK_DISCOVERY)
        );

        assertThat(plan.steps())
                .noneMatch(s -> s.mode() == RetrievalMode.HYBRID);
    }

    @Test
    @DisplayName("Plan always includes FILTERED_VECTOR step on control_index with topK=5")
    void plan_alwaysIncludesFilteredVectorOnControlIndex() {
        RetrievalPlan plan = planner.plan(
                buildRequest("INITIAL"),
                buildProfile(RetrievalIntent.BASELINE_RISK_DISCOVERY)
        );

        assertThat(plan.steps())
                .anyMatch(s -> s.mode() == RetrievalMode.FILTERED_VECTOR
                        && "control_index".equals(s.index())
                        && Integer.valueOf(5).equals(s.topK()));
    }

    @Test
    @DisplayName("RECALCULATION adds MEMORY_LOOKUP on assessment_history_index")
    void recalculation_addsMemoryLookup() {
        RetrievalPlan plan = planner.plan(
                buildRequest("RECALCULATION"),
                buildProfile(RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE)
        );

        assertThat(plan.steps())
                .anyMatch(s -> s.mode() == RetrievalMode.MEMORY_LOOKUP
                        && "assessment_history_index".equals(s.index()));
    }

    @Test
    @DisplayName("AUDIT adds MEMORY_LOOKUP on assessment_history_index")
    void audit_addsMemoryLookup() {
        RetrievalPlan plan = planner.plan(
                buildRequest("AUDIT"),
                buildProfile(RetrievalIntent.EXACT_CONTROL_EVIDENCE)
        );

        assertThat(plan.steps())
                .anyMatch(s -> s.mode() == RetrievalMode.MEMORY_LOOKUP
                        && "assessment_history_index".equals(s.index()));
    }

    @Test
    @DisplayName("INITIAL type does NOT add MEMORY_LOOKUP")
    void initial_doesNotAddMemoryLookup() {
        RetrievalPlan plan = planner.plan(
                buildRequest("INITIAL"),
                buildProfile(RetrievalIntent.BASELINE_RISK_DISCOVERY)
        );

        assertThat(plan.steps())
                .noneMatch(s -> s.mode() == RetrievalMode.MEMORY_LOOKUP);
    }

    @Test
    @DisplayName("RECALCULATION plan has exactly 4 steps")
    void recalculation_planHasFourSteps() {
        RetrievalPlan plan = planner.plan(
                buildRequest("RECALCULATION"),
                buildProfile(RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE)
        );

        assertThat(plan.steps()).hasSize(4);
    }
}
