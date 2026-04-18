package com.example.riskcalculator.domain.model;

import com.example.riskcalculator.domain.enums.RetrievalMode;

import java.util.List;
import java.util.Map;

/**
 * Raw result returned by the executor for a single retrieval step.
 * The payload contains the retrieved documents/records (as generic maps).
 */
public record RetrievalResult(
        RetrievalMode mode,
        String index,
        List<Map<String, Object>> payload
) {}
