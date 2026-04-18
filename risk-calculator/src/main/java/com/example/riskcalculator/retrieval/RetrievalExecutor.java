package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalResult;

import java.util.List;

/**
 * Executes a {@link RetrievalPlan} and returns a list of raw results.
 * Concrete implementations connect to actual data sources (Redis, vector DBs, etc.).
 * In V1 a stub implementation is used.
 */
public interface RetrievalExecutor {

    List<RetrievalResult> execute(RetrievalPlan plan);
}
