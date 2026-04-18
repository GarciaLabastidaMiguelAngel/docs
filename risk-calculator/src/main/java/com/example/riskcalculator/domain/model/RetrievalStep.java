package com.example.riskcalculator.domain.model;

import com.example.riskcalculator.domain.enums.RetrievalMode;

import java.util.Map;

/**
 * A single step in the retrieval plan, targeting one index with
 * a specific retrieval mode and optional filters / topK.
 */
public record RetrievalStep(
        RetrievalMode mode,
        String index,
        Map<String, String> filters,
        Integer topK
) {

    /** Convenience factory for steps that do not require a topK limit. */
    public static RetrievalStep of(RetrievalMode mode, String index, Map<String, String> filters) {
        return new RetrievalStep(mode, index, filters, null);
    }

    /** Convenience factory for steps that require a topK limit. */
    public static RetrievalStep of(RetrievalMode mode, String index, Map<String, String> filters, int topK) {
        return new RetrievalStep(mode, index, filters, topK);
    }
}
