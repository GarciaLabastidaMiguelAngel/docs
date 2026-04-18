package com.example.riskcalculator.audit;

import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;

/**
 * Records audit events at key stages of the contextualization pipeline.
 * Implementations may write to logs, databases, or event streams.
 */
public interface AuditService {

    void auditRequest(RiskAssessmentRequest request);

    void auditContextProfile(String assessmentId, ContextProfile profile);

    void auditRetrievalPlan(String assessmentId, RetrievalPlan plan);

    void auditEvidenceBundle(String assessmentId, EvidenceBundle bundle);
}
