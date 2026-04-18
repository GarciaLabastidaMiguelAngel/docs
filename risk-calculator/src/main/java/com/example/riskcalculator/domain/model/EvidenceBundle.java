package com.example.riskcalculator.domain.model;

import java.util.List;
import java.util.Map;

/**
 * Consolidated bundle of evidence ready for risk scoring in V2.
 * In V1 all lists are empty (stub retrieval).
 */
public record EvidenceBundle(
        List<Map<String, Object>> assets,
        List<Map<String, Object>> findings,
        List<Map<String, Object>> controls,
        List<Map<String, Object>> incidents,
        List<Map<String, Object>> assessmentHistory
) {

    /** Returns an empty evidence bundle. */
    public static EvidenceBundle empty() {
        return new EvidenceBundle(
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
