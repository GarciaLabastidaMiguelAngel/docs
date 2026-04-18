# Risk Calculator – Adaptive Enterprise Risk Contextualisation Engine (V1)

## Propósito

Este proyecto implementa la **primera versión** de una calculadora de riesgo adaptativa
para entornos enterprise. En esta versión el objetivo no es calcular el score de riesgo
final, sino construir la **capa cognitiva/contextual** que:

1. Recibe una solicitud de evaluación de riesgo.
2. Entiende el contexto del activo y la solicitud.
3. Genera un perfil contextual.
4. Decide qué estrategia de retrieval aplicar.
5. Ejecuta ese plan mediante un executor desacoplado.
6. Consolida la evidencia.
7. Devuelve una respuesta con status `READY_FOR_RISK_SCORING`.

---

## Arquitectura

El proyecto sigue una arquitectura de **modular monolith** con capas bien definidas:

```
src/main/java/com/example/riskcalculator/
├── api/                         # Controladores REST (capa de entrada)
├── application/                 # Orquestador del pipeline
├── domain/
│   ├── model/                   # Records de dominio (inmutables)
│   └── enums/                   # Enumeraciones de dominio
├── context/                     # Lógica de profiling contextual
├── retrieval/                   # Planificación, ejecución y ensamblado de evidencia
├── audit/                       # Servicio de auditoría
└── infrastructure/
    └── config/                  # Configuración de beans
```

Cada capa sólo depende hacia adentro, siguiendo los principios de **Clean Architecture**.

---

## Flujo del Pipeline

```
POST /risk-assessments/contextualize
            │
            ▼
   RiskAssessmentController          (valida el request con Jakarta Validation)
            │
            ▼
   RiskAssessmentOrchestrator        (orquesta las 5 etapas)
            │
    ┌───────┴───────┐
    │               │
    ▼               ▼
ContextProfiler   AuditService      (genera perfil + audita)
    │
    ▼
RetrievalStrategyPlanner            (planifica pasos de retrieval)
    │
    ▼
RetrievalExecutor (Stub en V1)      (ejecuta el plan)
    │
    ▼
EvidenceAssembler                   (consolida resultados en EvidenceBundle)
    │
    ▼
ContextualizedAssessmentResponse    (status = READY_FOR_RISK_SCORING)
```

---

## Endpoint

### `POST /risk-assessments/contextualize`

#### Request

```json
{
  "assessmentId": "A-1001",
  "assetType": "REPOSITORY",
  "assetId": "payments-api",
  "domain": "OPERATIONAL",
  "criticality": "HIGH",
  "assessmentType": "RECALCULATION",
  "signals": ["availability_findings", "control_evidence_expired"],
  "technology": "JAVA",
  "tags": ["api", "payments", "customer-facing"],
  "timeHorizonDays": 90
}
```

#### Response `200 OK`

```json
{
  "assessmentId": "A-1001",
  "contextProfile": {
    "retrievalIntent": "RECENT_OPERATIONAL_EVIDENCE",
    "freshnessRequired": "HIGH",
    "explainabilityRequired": true,
    "confidenceNeed": "HIGH"
  },
  "retrievalPlan": {
    "steps": [
      {
        "mode": "EXACT",
        "index": "asset_index",
        "filters": { "assetId": "payments-api" },
        "topK": null
      },
      {
        "mode": "HYBRID",
        "index": "finding_index",
        "filters": { "domain": "OPERATIONAL", "technology": "JAVA" },
        "topK": 10
      },
      {
        "mode": "FILTERED_VECTOR",
        "index": "control_index",
        "filters": { "assetType": "REPOSITORY", "criticality": "HIGH" },
        "topK": 5
      },
      {
        "mode": "MEMORY_LOOKUP",
        "index": "assessment_history_index",
        "filters": { "assetId": "payments-api" },
        "topK": null
      }
    ]
  },
  "evidenceBundle": {
    "assets": [],
    "findings": [],
    "controls": [],
    "incidents": [],
    "assessmentHistory": []
  },
  "status": "READY_FOR_RISK_SCORING"
}
```

---

## Requisitos

| Herramienta | Versión mínima |
|-------------|---------------|
| Java        | 17 (diseñado para 21+) |
| Maven       | 3.9+          |
| Spring Boot | 3.2.x         |

---

## Ejecución

```bash
# Compilar y ejecutar tests
cd risk-calculator
mvn clean verify

# Levantar el servidor
mvn spring-boot:run

# Probar el endpoint
curl -s -X POST http://localhost:8080/risk-assessments/contextualize \
  -H "Content-Type: application/json" \
  -d '{
    "assessmentId": "A-1001",
    "assetType": "REPOSITORY",
    "assetId": "payments-api",
    "domain": "OPERATIONAL",
    "criticality": "HIGH",
    "assessmentType": "RECALCULATION",
    "signals": ["availability_findings", "control_evidence_expired"],
    "technology": "JAVA",
    "tags": ["api", "payments", "customer-facing"],
    "timeHorizonDays": 90
  }' | jq .
```

---

## Reglas de Negocio

### ContextProfiler

| Condición | Resultado |
|-----------|-----------|
| `assessmentType = INITIAL` | `retrievalIntent = BASELINE_RISK_DISCOVERY` |
| `assessmentType = RECALCULATION` | `retrievalIntent = RECENT_OPERATIONAL_EVIDENCE` |
| `assessmentType = AUDIT` | `retrievalIntent = EXACT_CONTROL_EVIDENCE` |
| `criticality = HIGH` | `explainabilityRequired = true` |
| signals contiene `availability_findings` o `control_evidence_expired` | `freshnessRequired = HIGH` |
| por defecto | `freshnessRequired = MEDIUM` |
| siempre | `confidenceNeed = HIGH` |

### RetrievalStrategyPlanner

| Condición | Acción |
|-----------|--------|
| Siempre | `EXACT` en `asset_index` filtrando `assetId` |
| intent = `RECENT_OPERATIONAL_EVIDENCE` | `HYBRID` en `finding_index` con `domain + technology`, `topK = 10` |
| Siempre | `FILTERED_VECTOR` en `control_index` con `assetType + criticality`, `topK = 5` |
| `assessmentType = RECALCULATION` o `AUDIT` | `MEMORY_LOOKUP` en `assessment_history_index` filtrando `assetId` |

---

## Árbol del Proyecto

```
risk-calculator/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/com/example/riskcalculator/
    │   │   ├── RiskCalculatorApplication.java
    │   │   ├── api/
    │   │   │   └── RiskAssessmentController.java
    │   │   ├── application/
    │   │   │   └── RiskAssessmentOrchestrator.java
    │   │   ├── domain/
    │   │   │   ├── enums/
    │   │   │   │   ├── ConfidenceNeed.java
    │   │   │   │   ├── FreshnessLevel.java
    │   │   │   │   ├── RetrievalIntent.java
    │   │   │   │   └── RetrievalMode.java
    │   │   │   └── model/
    │   │   │       ├── ContextProfile.java
    │   │   │       ├── ContextualizedAssessmentResponse.java
    │   │   │       ├── EvidenceBundle.java
    │   │   │       ├── RetrievalPlan.java
    │   │   │       ├── RetrievalResult.java
    │   │   │       ├── RetrievalStep.java
    │   │   │       └── RiskAssessmentRequest.java
    │   │   ├── context/
    │   │   │   ├── ContextProfiler.java
    │   │   │   └── DefaultContextProfiler.java
    │   │   ├── retrieval/
    │   │   │   ├── DefaultEvidenceAssembler.java
    │   │   │   ├── DefaultRetrievalStrategyPlanner.java
    │   │   │   ├── EvidenceAssembler.java
    │   │   │   ├── RetrievalExecutor.java
    │   │   │   ├── RetrievalStrategyPlanner.java
    │   │   │   └── StubRetrievalExecutor.java
    │   │   ├── audit/
    │   │   │   ├── AuditService.java
    │   │   │   └── LoggingAuditService.java
    │   │   └── infrastructure/
    │   │       └── config/
    │   │           └── AppConfig.java
    │   └── resources/
    │       └── application.properties
    └── test/
        └── java/com/example/riskcalculator/
            ├── application/
            │   └── RiskAssessmentOrchestratorTest.java
            ├── context/
            │   └── DefaultContextProfilerTest.java
            └── retrieval/
                └── DefaultRetrievalStrategyPlannerTest.java
```

---

## Siguientes Pasos (Roadmap)

### V2 – Integración con Redis
- Reemplazar `StubRetrievalExecutor` con implementaciones reales por modo:
  - `EXACT` → Redis Hash / Search
  - `HYBRID` → Redis Search (full-text + vector)
  - `FILTERED_VECTOR` → Redis VSS (Vector Similarity Search)
  - `MEMORY_LOOKUP` → Redis Stream / sorted set

### V3 – Motor de Scoring
- Implementar `RiskScoreCalculator` que consuma el `EvidenceBundle`
- Añadir pesos por dominio, criticidad y señales activas
- Producir un `RiskScore` con breakdown por componente

### V4 – Riesgo Observado
- Integrar feeds de observabilidad (métricas, alertas, SLOs)
- Incorporar datos de incidentes en tiempo real al bundle

### V5 – Calibración
- Registrar feedback sobre scores pasados
- Ajustar pesos del modelo vía un servicio de calibración bayesiana

### V6 – Gobernanza
- Añadir trazabilidad completa de decisiones (audit trail inmutable)
- Control de versiones del modelo de scoring
- Dashboard de explicabilidad para auditores
