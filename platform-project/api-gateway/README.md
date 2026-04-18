# Componente: API Gateway

Punto de entrada único para todas las peticiones externas hacia los servicios internos de la plataforma.

## Responsabilidades

- Enrutar solicitudes hacia el componente correcto (`auth`, `ui`, etc.).
- Validar tokens JWT antes de reenviar la solicitud.
- Rate limiting y circuit breaker.
- Logging centralizado de peticiones.

## Tecnologías sugeridas

- **Spring Cloud Gateway** (Java / Spring Boot)
- **Netflix Zuul** (alternativa)

## Rutas configuradas

| Ruta de entrada       | Componente destino |
|-----------------------|--------------------|
| `/auth/**`            | auth               |
| `/api/**`             | servicios internos |
| `/ui/**`              | ui                 |
