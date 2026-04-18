package com.example.riskcalculator.retrieval;

import com.example.riskcalculator.domain.model.EvidenceBundle;
import com.example.riskcalculator.domain.model.RetrievalResult;

import java.util.List;

/**
 * Assembles a list of raw {@link RetrievalResult}s into a structured
 * {@link EvidenceBundle} ready for risk scoring.
 */
public interface EvidenceAssembler {

    EvidenceBundle assemble(List<RetrievalResult> results);
}
