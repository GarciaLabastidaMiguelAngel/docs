# Platform Project

Este repositorio contiene la estructura de una **plataforma** organizada en **componentes**.

## ¿Puede una plataforma tener componentes?

**Sí.** Una plataforma puede (y debe) estar dividida en componentes independientes que colaboran entre sí. Esto permite:

- **Escalabilidad**: cada componente crece de forma independiente.
- **Mantenibilidad**: equipos distintos pueden trabajar en componentes distintos.
- **Reutilización**: los componentes se pueden usar en otros proyectos.

## Componentes de esta plataforma

| Componente    | Descripción                                      |
|---------------|--------------------------------------------------|
| `auth`        | Autenticación y autorización (JWT / OAuth2)      |
| `api-gateway` | Puerta de entrada única para todos los servicios |
| `ui`          | Interfaz de usuario (frontend)                   |

## Estructura del proyecto

```
platform-project/
├── auth/
│   └── README.md
├── api-gateway/
│   └── README.md
├── ui/
│   └── README.md
└── README.md   ← este archivo
```

## Cómo ejecutar

Cada componente tiene sus propias instrucciones de ejecución en su `README.md` respectivo.
