# Componente: Auth

Responsable de la **autenticación y autorización** de usuarios dentro de la plataforma.

## Responsabilidades

- Registro e inicio de sesión de usuarios.
- Generación y validación de tokens JWT.
- Integración con proveedores OAuth2 (Google, GitHub, etc.).
- Control de roles y permisos.

## Tecnologías sugeridas

- **Spring Security** (Java / Spring Boot)
- **Keycloak** como servidor de identidad

## Endpoints principales

| Método | Ruta            | Descripción                  |
|--------|-----------------|------------------------------|
| POST   | `/auth/login`   | Inicia sesión y devuelve JWT |
| POST   | `/auth/register`| Registra un nuevo usuario    |
| POST   | `/auth/refresh` | Renueva el token de acceso   |
| POST   | `/auth/logout`  | Invalida el token actual     |
