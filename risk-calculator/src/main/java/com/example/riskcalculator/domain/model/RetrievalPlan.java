package com.example.riskcalculator.domain.model;

import java.util.List;

/**
 * The full retrieval plan, containing an ordered list of steps
 * to be executed by the RetrievalExecutor.
 */
public record RetrievalPlan(List<RetrievalStep> steps) {}
