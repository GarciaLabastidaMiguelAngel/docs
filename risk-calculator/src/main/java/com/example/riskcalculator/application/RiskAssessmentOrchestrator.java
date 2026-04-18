package com.example.riskcalculator.application;

import com.example.riskcalculator.audit.AuditService;
import com.example.riskcalculator.context.ContextProfiler;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.ContextualizedAssessmentResponse;
import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalResult;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import com.example.riskcalculator.retrieval.EvidenceAssembler;
import com.example.riskcalculator.retrieval.RetrievalExecutor;
import com.example.riskcalculator.retrieval.RetrievalStrategyPlanner;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Orchestrates the full contextualisation pipeline for a risk assessment request.
 *
 * <p>Pipeline stages:
 * <ol>
 *   <li>Audit the raw request.</li>
 *   <li>Build a context profile from the request.</li>
 *   <li>Plan the retrieval strategy.</li>
 *   <li>Execute the plan via the retrieval executor.</li>
 *   <li>Assemble raw results into an evidence bundle.</li>
 *   <li>Return a {@link ContextualizedAssessmentResponse} with status READY_FOR_RISK_SCORING.</li>
 * </ol>
 */
@Service
public class RiskAssessmentOrchestrator {

    private static final String STATUS_READY = "READY_FOR_RISK_SCORING";

    private final ContextProfiler contextProfiler;
    private final RetrievalStrategyPlanner retrievalStrategyPlanner;
    private final RetrievalExecutor retrievalExecutor;
    private final EvidenceAssembler evidenceAssembler;
    private final AuditService auditService;

    public RiskAssessmentOrchestrator(
            ContextProfiler contextProfiler,
            RetrievalStrategyPlanner retrievalStrategyPlanner,
            RetrievalExecutor retrievalExecutor,
            EvidenceAssembler evidenceAssembler,
            AuditService auditService) {
        this.contextProfiler = contextProfiler;
        this.retrievalStrategyPlanner = retrievalStrategyPlanner;
        this.retrievalExecutor = retrievalExecutor;
        this.evidenceAssembler = evidenceAssembler;
        this.auditService = auditService;
    }

    /**
     * Runs the contextualisation pipeline and returns a response ready for risk scoring.
     *
     * @param request the validated assessment request
     * @return a contextualised assessment response
     */
    public ContextualizedAssessmentResponse contextualize(RiskAssessmentRequest request) {
        // Stage 1 – audit incoming request
        auditService.auditRequest(request);

        // Stage 2 – build context profile
        ContextProfile contextProfile = contextProfiler.profile(request);
        auditService.auditContextProfile(request.assessmentId(), contextProfile);

        // Stage 3 – plan retrieval
        RetrievalPlan retrievalPlan = retrievalStrategyPlanner.plan(request, contextProfile);
        auditService.auditRetrievalPlan(request.assessmentId(), retrievalPlan);

        // Stage 4 – execute retrieval
        List<RetrievalResult> results = retrievalExecutor.execute(retrievalPlan);

        // Stage 5 – assemble evidence bundle
        EvidenceBundle evidenceBundle = evidenceAssembler.assemble(results);
        auditService.auditEvidenceBundle(request.assessmentId(), evidenceBundle);

        // Stage 6 – build and return response
        return new ContextualizedAssessmentResponse(
                request.assessmentId(),
                contextProfile,
                retrievalPlan,
                evidenceBundle,
                STATUS_READY
        );
    }
}
