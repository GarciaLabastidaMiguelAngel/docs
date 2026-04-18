package com.example.riskcalculator.application;

import com.example.riskcalculator.audit.AuditService;
import com.example.riskcalculator.context.ContextProfiler;
import com.example.riskcalculator.domain.enums.ConfidenceNeed;
import com.example.riskcalculator.domain.enums.FreshnessLevel;
import com.example.riskcalculator.domain.enums.RetrievalIntent;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.ContextualizedAssessmentResponse;
import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalResult;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import com.example.riskcalculator.retrieval.EvidenceAssembler;
import com.example.riskcalculator.retrieval.RetrievalExecutor;
import com.example.riskcalculator.retrieval.RetrievalStrategyPlanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RiskAssessmentOrchestratorTest {

    @Mock private ContextProfiler contextProfiler;
    @Mock private RetrievalStrategyPlanner retrievalStrategyPlanner;
    @Mock private RetrievalExecutor retrievalExecutor;
    @Mock private EvidenceAssembler evidenceAssembler;
    @Mock private AuditService auditService;

    private RiskAssessmentOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        orchestrator = new RiskAssessmentOrchestrator(
                contextProfiler, retrievalStrategyPlanner,
                retrievalExecutor, evidenceAssembler, auditService
        );
    }

    private RiskAssessmentRequest buildRequest() {
        return new RiskAssessmentRequest(
                "A-1001", "REPOSITORY", "payments-api",
                "OPERATIONAL", "HIGH", "RECALCULATION",
                List.of("availability_findings", "control_evidence_expired"),
                "JAVA", List.of("api", "payments"), 90
        );
    }

    @Test
    @DisplayName("Full pipeline returns READY_FOR_RISK_SCORING status")
    void fullPipeline_returnsReadyForRiskScoringStatus() {
        RiskAssessmentRequest request = buildRequest();

        ContextProfile profile = new ContextProfile(
                RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE,
                FreshnessLevel.HIGH, true, ConfidenceNeed.HIGH
        );
        RetrievalPlan plan = new RetrievalPlan(List.of());
        EvidenceBundle bundle = EvidenceBundle.empty();

        when(contextProfiler.profile(request)).thenReturn(profile);
        when(retrievalStrategyPlanner.plan(request, profile)).thenReturn(plan);
        when(retrievalExecutor.execute(plan)).thenReturn(List.of());
        when(evidenceAssembler.assemble(any())).thenReturn(bundle);

        ContextualizedAssessmentResponse response = orchestrator.contextualize(request);

        assertThat(response.status()).isEqualTo("READY_FOR_RISK_SCORING");
    }

    @Test
    @DisplayName("Response carries the same assessmentId as the request")
    void response_carriesCorrectAssessmentId() {
        RiskAssessmentRequest request = buildRequest();

        ContextProfile profile = new ContextProfile(
                RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE,
                FreshnessLevel.HIGH, true, ConfidenceNeed.HIGH
        );
        RetrievalPlan plan = new RetrievalPlan(List.of());
        EvidenceBundle bundle = EvidenceBundle.empty();

        when(contextProfiler.profile(request)).thenReturn(profile);
        when(retrievalStrategyPlanner.plan(request, profile)).thenReturn(plan);
        when(retrievalExecutor.execute(plan)).thenReturn(List.of());
        when(evidenceAssembler.assemble(any())).thenReturn(bundle);

        ContextualizedAssessmentResponse response = orchestrator.contextualize(request);

        assertThat(response.assessmentId()).isEqualTo("A-1001");
    }

    @Test
    @DisplayName("Response contains the context profile returned by the profiler")
    void response_containsContextProfileFromProfiler() {
        RiskAssessmentRequest request = buildRequest();

        ContextProfile profile = new ContextProfile(
                RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE,
                FreshnessLevel.HIGH, true, ConfidenceNeed.HIGH
        );
        RetrievalPlan plan = new RetrievalPlan(List.of());
        EvidenceBundle bundle = EvidenceBundle.empty();

        when(contextProfiler.profile(request)).thenReturn(profile);
        when(retrievalStrategyPlanner.plan(request, profile)).thenReturn(plan);
        when(retrievalExecutor.execute(plan)).thenReturn(List.of());
        when(evidenceAssembler.assemble(any())).thenReturn(bundle);

        ContextualizedAssessmentResponse response = orchestrator.contextualize(request);

        assertThat(response.contextProfile()).isEqualTo(profile);
    }

    @Test
    @DisplayName("All pipeline stages are invoked in order")
    void pipelineStages_areAllInvoked() {
        RiskAssessmentRequest request = buildRequest();

        ContextProfile profile = new ContextProfile(
                RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE,
                FreshnessLevel.HIGH, true, ConfidenceNeed.HIGH
        );
        RetrievalPlan plan = new RetrievalPlan(List.of());
        List<RetrievalResult> results = List.of();
        EvidenceBundle bundle = EvidenceBundle.empty();

        when(contextProfiler.profile(request)).thenReturn(profile);
        when(retrievalStrategyPlanner.plan(request, profile)).thenReturn(plan);
        when(retrievalExecutor.execute(plan)).thenReturn(results);
        when(evidenceAssembler.assemble(results)).thenReturn(bundle);

        orchestrator.contextualize(request);

        verify(auditService).auditRequest(request);
        verify(auditService).auditContextProfile(request.assessmentId(), profile);
        verify(auditService).auditRetrievalPlan(request.assessmentId(), plan);
        verify(auditService).auditEvidenceBundle(request.assessmentId(), bundle);
        verify(contextProfiler).profile(request);
        verify(retrievalStrategyPlanner).plan(request, profile);
        verify(retrievalExecutor).execute(plan);
        verify(evidenceAssembler).assemble(results);
    }
}
