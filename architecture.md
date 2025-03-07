# Architecture Overview

This document outlines the architecture for a multi-tenant SAAS application using Rust, Axum, SQLx, MiniJinja, HTMX, Tailwind CSS, Docker, and Postgres.

## Database
- Use auto incrementing primary keys (with sequences) instead of UUIDs for identifiers for better indexing performance.
- Utilize PostgreSQL with Row Level Security (RLS), but follow the guidance in this article for implementing RLS, particularly the "Alternative approach" section for the tenant isolation policy: postgres_tenant_isolation.md
- Each table will include a `tenant_id` column to filter data per tenant.
- At its core, the database will have a `usr` table that will hold the users of the platform.
- Create a role table to define system roles, and descriptions for each role.  Start with ADMIN (platform administrators), INTERNAL (internal SAAS platform access to reports, analytics, etc), TENANT_SUPER (a tenant superuser who can perform administrative functions within a tenant).
- Create a user_role table to link users to roles at the platform level.
- Create a tenant table to hold the tenants.
- Create a tenant_member table to map users to tenants.  Users may have memberships to more than one tenant.
- Create a tenant_role table to map users to tenants and roles (ie: for assigning the TENANT_SUPER role for a specific tenant).
- Admin users can switch tenant contexts by selecting a tenant from the UI, which updates the JWT token with the new tenant context. System-wide data access is facilitated by omitting the `tenant_id` in the JWT for admin routes.
- JWT tokens will store tenant context information by including the `tenant_id` as a claim within the token payload.
- Use SQLx for database schema migrations and versioning. This will ensure that the database schema is consistently applied across different environments.
- The initial schema will be populated into the database using SQLx migration scripts, which will be executed during the application startup or deployment process.
- Develop migration scripts to handle schema changes as the application evolves, ensuring backward compatibility and smooth transitions between versions.

## HTTP Routing
- Axum will handle HTTP requests.
- Tower middleware will manage authentication, CORS, and security.
- Routes will be clearly separated into tenant-specific and admin-specific endpoints.
- Custom Tower middleware will be developed to extract the `tenant_id` from JWT tokens and apply it to requests. This middleware will check for the presence of a `tenant_id` claim and set it in the request context.
- Custom Tower middleware will be developed to extract the `user_id` from JWT tokens and query the service layer for the user's roles as defined under the database section, and set this "AuthContext" or other data structure into the request context, so Axum/Tower can use this information for handling security checks to routes.
- **Route Security**: Axum/Tower will validate that the currently logged-in user, and their AuthContext, linked to their chosen tenant context, has access to the routes they are requesting. For example:
  - An ADMIN user will have access to all routes and all tenant contexts.
  - A TENANT_SUPER user will have access to certain tenant administrative routes if they hold the TENANT_SUPER tenant_role for the tenant context they are currently using.
  - A regular user with no other roles needs to hold a tenant_member mapping to access tenant-specific routes but will not be restricted from accessing certain global routes (such as viewing and/or updating their user profile).

## Services
- Services will encapsulate business logic and interact with data access layers.
- Clearly defined interfaces for each service to ensure modularity and ease of testing.
- Context switching will be handled by an AuthService, which has methods that accept a user and `tenant_id` parameter.  The service will perform security checks to ensure the user is allowed to switch to the given `tenant_id`.
- Services will accept a `tenant_id` parameter in service method invocations, which will flow through to the data access layer.

## Data Access
- SQLx will be used for database interactions.
- Data access layers will enforce tenant isolation by automatically applying tenant filters. This will be achieved by including the `tenant_id` in SQL queries to filter results at the database level, enhancing performance by leveraging PostgreSQL's query planner.
- Admin-specific data access layers will bypass tenant filters for system-wide analytics and reporting by omitting the `tenant_id` in queries.

## Views
- MiniJinja will render server-side templates.
- HTMX will handle dynamic interactions and partial page updates. The initial page will be rendered with MiniJinja, and subsequent interactions, such as form submissions and data updates, will be handled by Axum endpoints that return updated HTML fragments rendered by MiniJinja, which HTMX will use to update the view.

## CSS
- Tailwind CSS will be used for styling without Node.js.
- CSS will be compiled and optimized using Rust-based tooling such as `tailwindcss-rs` or `cargo-watch` to automate the build process. This will ensure that styles are efficiently bundled and minimized for production.

## Build and Deployment
- Docker will containerize the application for consistent deployment.
- CI/CD pipelines will automate testing, building, and deployment.
- Environment variables will manage configuration across different environments.
- Deployment strategies will support scalability and high availability without adding complexity via Kubernetes.

This architecture aims to provide a robust, secure, and extensible foundation for developing various multi-tenant SAAS applications. 