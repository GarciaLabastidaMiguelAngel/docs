package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalResult;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default implementation of {@link EvidenceAssembler}.
 *
 * <p>Routes raw retrieval results into the correct slot of {@link EvidenceBundle}
 * based on the source index name.  In V1 all payloads are empty (stub),
 * but the routing logic is already wired for V2.
 */
@Component
public class DefaultEvidenceAssembler implements EvidenceAssembler {

    @Override
    public EvidenceBundle assemble(List<RetrievalResult> results) {
        List<Map<String, Object>> assets            = new ArrayList<>();
        List<Map<String, Object>> findings          = new ArrayList<>();
        List<Map<String, Object>> controls          = new ArrayList<>();
        List<Map<String, Object>> incidents         = new ArrayList<>();
        List<Map<String, Object>> assessmentHistory = new ArrayList<>();

        for (RetrievalResult result : results) {
            switch (result.index()) {
                case "asset_index"              -> assets.addAll(result.payload());
                case "finding_index"            -> findings.addAll(result.payload());
                case "control_index"            -> controls.addAll(result.payload());
                case "incident_index"           -> incidents.addAll(result.payload());
                case "assessment_history_index" -> assessmentHistory.addAll(result.payload());
                default -> { /* unknown index – ignore */ }
            }
        }

        return new EvidenceBundle(
                List.copyOf(assets),
                List.copyOf(findings),
                List.copyOf(controls),
                List.copyOf(incidents),
                List.copyOf(assessmentHistory)
        );
    }
}
