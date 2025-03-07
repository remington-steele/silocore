# SiloCore - Multi-Tenant SAAS Application

SiloCore is a multi-tenant SAAS application built with Rust, Axum, SQLx, MiniJinja, HTMX, and Tailwind CSS.

## Features

- Multi-tenant architecture with Row Level Security (RLS) for data isolation
- JWT-based authentication and authorization
- Role-based access control at both platform and tenant levels
- Server-side rendering with MiniJinja templates
- Dynamic UI interactions with HTMX
- Modern styling with Tailwind CSS

## Prerequisites

- Rust (latest stable version)
- PostgreSQL 12+
- Docker (optional, for containerized deployment)

## JWT Configuration

The application uses JSON Web Tokens (JWT) for authentication and tenant context management. The following environment variables are used for JWT configuration:

- `JWT_SECRET`: Secret key used for signing and verifying JWT tokens. This should be a strong, random string.
- `JWT_EXPIRATION_SECONDS`: Token expiration time in seconds. Defaults to 86400 (24 hours) if not specified.
- `JWT_ISSUER`: Issuer claim value for the JWT tokens. Defaults to "silocore" if not specified.

### JWT Token Structure

The JWT tokens include the following claims:

- `sub`: Subject (user ID)
- `tid`: Optional tenant ID for tenant context
- `roles`: System roles assigned to the user
- `tenant_roles`: Tenant roles assigned to the user (if tenant context is set)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `iss`: Issuer

### Tenant Context Switching

Admin users can switch tenant contexts by selecting a tenant from the UI, which updates the JWT token with the new tenant context. System-wide data access is facilitated by omitting the `tenant_id` in the JWT for admin routes.

## Environment Variables

Create a `.env` file in the project root with the following variables:

```
DATABASE_URL=postgres://username:password@localhost:5432/silocore
DATABASE_ADMIN_URL=postgres://admin:password@localhost:5432/silocore
JWT_SECRET=your_secret_key_here
JWT_EXPIRATION_SECONDS=86400
JWT_ISSUER=silocore
```

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/silocore.git
   cd silocore
   ```

2. Set up the PostgreSQL database:
   ```
   psql -U postgres -f sql/init/init.sql
   ```

3. Run the application:
   ```
   cargo run
   ```