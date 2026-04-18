package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.model.RetrievalPlan;
import com.example.riskcalculator.domain.model.RetrievalResult;
import com.example.riskcalculator.domain.model.RetrievalStep;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Stub implementation of {@link RetrievalExecutor}.
 * Returns empty payloads for every step in the plan.
 *
 * <p>TODO: Replace with a real Redis / vector-DB backed executor in V2.
 * Each step should be dispatched to its corresponding data source
 * based on {@link com.example.riskcalculator.domain.enums.RetrievalMode}.
 */
@Component
public class StubRetrievalExecutor implements RetrievalExecutor {

    private static final Logger log = LoggerFactory.getLogger(StubRetrievalExecutor.class);

    @Override
    public List<RetrievalResult> execute(RetrievalPlan plan) {
        return plan.steps().stream()
                .map(this::executeStep)
                .toList();
    }

    private RetrievalResult executeStep(RetrievalStep step) {
        log.debug("Stub executing step: mode={} index={} filters={}",
                step.mode(), step.index(), step.filters());
        // TODO: integrate with Redis / vector store per mode
        return new RetrievalResult(step.mode(), step.index(), List.of());
    }
}
