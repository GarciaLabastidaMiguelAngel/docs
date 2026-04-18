# Componente: UI

Interfaz de usuario de la plataforma. Consume los servicios expuestos por el API Gateway.

## Responsabilidades

- Presentar la información al usuario final.
- Gestionar el flujo de autenticación (login / registro).
- Comunicarse con el backend a través del API Gateway.

## Tecnologías sugeridas

- **React** o **Angular**
- **Axios** para llamadas HTTP
- **React Router** para navegación

## Páginas principales

| Ruta          | Descripción                     |
|---------------|---------------------------------|
| `/login`      | Pantalla de inicio de sesión    |
| `/register`   | Pantalla de registro            |
| `/dashboard`  | Panel principal del usuario     |
| `/profile`    | Perfil del usuario autenticado  |
