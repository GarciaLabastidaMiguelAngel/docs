package com.example.riskcalculator.audit;

import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Simple structured-logging implementation of {@link AuditService}.
 * Each audit event is emitted as a single INFO log line.
 *
 * <p>Replace or augment this with a persistent audit store in future versions.
 */
@Component
public class LoggingAuditService implements AuditService {

    private static final Logger log = LoggerFactory.getLogger(LoggingAuditService.class);

    @Override
    public void auditRequest(RiskAssessmentRequest request) {
        log.info("[AUDIT] REQUEST received: assessmentId={} assetId={} assetType={} " +
                        "domain={} criticality={} assessmentType={} technology={} signals={}",
                request.assessmentId(),
                request.assetId(),
                request.assetType(),
                request.domain(),
                request.criticality(),
                request.assessmentType(),
                request.technology(),
                request.signals());
    }

    @Override
    public void auditContextProfile(String assessmentId, ContextProfile profile) {
        log.info("[AUDIT] CONTEXT_PROFILE: assessmentId={} intent={} freshness={} " +
                        "explainability={} confidence={}",
                assessmentId,
                profile.retrievalIntent(),
                profile.freshnessRequired(),
                profile.explainabilityRequired(),
                profile.confidenceNeed());
    }

    @Override
    public void auditRetrievalPlan(String assessmentId, RetrievalPlan plan) {
        log.info("[AUDIT] RETRIEVAL_PLAN: assessmentId={} steps={}",
                assessmentId, plan.steps().size());
        plan.steps().forEach(step ->
                log.info("[AUDIT]   step: mode={} index={} filters={} topK={}",
                        step.mode(), step.index(), step.filters(), step.topK()));
    }

    @Override
    public void auditEvidenceBundle(String assessmentId, EvidenceBundle bundle) {
        log.info("[AUDIT] EVIDENCE_BUNDLE: assessmentId={} assets={} findings={} " +
                        "controls={} incidents={} assessmentHistory={}",
                assessmentId,
                bundle.assets().size(),
                bundle.findings().size(),
                bundle.controls().size(),
                bundle.incidents().size(),
                bundle.assessmentHistory().size());
    }
}
