package com.example.riskcalculator.api;

import com.example.riskcalculator.application.RiskAssessmentOrchestrator;
import com.example.riskcalculator.domain.model.ContextualizedAssessmentResponse;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST entry point for the risk assessment contextualisation engine.
 */
@RestController
@RequestMapping("/risk-assessments")
public class RiskAssessmentController {

    private final RiskAssessmentOrchestrator orchestrator;

    public RiskAssessmentController(RiskAssessmentOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    /**
     * Contextualises a risk assessment request.
     *
     * <p>POST /risk-assessments/contextualize
     *
     * @param request the validated assessment request body
     * @return 200 OK with a {@link ContextualizedAssessmentResponse}
     */
    @PostMapping("/contextualize")
    public ResponseEntity<ContextualizedAssessmentResponse> contextualize(
            @Valid @RequestBody RiskAssessmentRequest request) {

        ContextualizedAssessmentResponse response = orchestrator.contextualize(request);
        return ResponseEntity.ok(response);
    }
}
