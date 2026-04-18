package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.enums.RetrievalIntent;
import com.example.riskcalculator.domain.enums.RetrievalMode;
import com.example.riskcalculator.domain.model.ContextProfile;
import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalStep;
import com.example.riskcalculator.domain.model.RiskAssessmentRequest;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default rule-based implementation of {@link RetrievalStrategyPlanner}.
 *
 * <p>Rules applied in order:
 * <ol>
 *   <li>Always add EXACT on asset_index filtering by assetId.</li>
 *   <li>If intent = RECENT_OPERATIONAL_EVIDENCE → add HYBRID on finding_index
 *       with domain + technology, topK = 10.</li>
 *   <li>Always add FILTERED_VECTOR on control_index with assetType + criticality, topK = 5.</li>
 *   <li>If assessmentType = RECALCULATION or AUDIT → add MEMORY_LOOKUP on
 *       assessment_history_index filtering by assetId.</li>
 * </ol>
 */
@Component
public class DefaultRetrievalStrategyPlanner implements RetrievalStrategyPlanner {

    @Override
    public RetrievalPlan plan(RiskAssessmentRequest request, ContextProfile contextProfile) {
        List<RetrievalStep> steps = new ArrayList<>();

        // Rule 1 – always exact lookup on asset index
        steps.add(RetrievalStep.of(
                RetrievalMode.EXACT,
                "asset_index",
                Map.of("assetId", request.assetId())
        ));

        // Rule 2 – hybrid finding search when recent operational evidence is needed
        if (contextProfile.retrievalIntent() == RetrievalIntent.RECENT_OPERATIONAL_EVIDENCE) {
            steps.add(RetrievalStep.of(
                    RetrievalMode.HYBRID,
                    "finding_index",
                    Map.of("domain", request.domain(), "technology", request.technology()),
                    10
            ));
        }

        // Rule 3 – always filtered vector search on control index
        steps.add(RetrievalStep.of(
                RetrievalMode.FILTERED_VECTOR,
                "control_index",
                Map.of("assetType", request.assetType(), "criticality", request.criticality()),
                5
        ));

        // Rule 4 – memory lookup for recalculation or audit types
        String assessmentType = request.assessmentType() == null ? "" : request.assessmentType().toUpperCase();
        if ("RECALCULATION".equals(assessmentType) || "AUDIT".equals(assessmentType)) {
            steps.add(RetrievalStep.of(
                    RetrievalMode.MEMORY_LOOKUP,
                    "assessment_history_index",
                    Map.of("assetId", request.assetId())
            ));
        }

        return new RetrievalPlan(List.copyOf(steps));
    }
}
