use anyhow::{Result, anyhow};
use sqlx::PgPool;
use tracing::{debug, error, info};
use time;

use crate::model::{AuthContext, SystemRole, User};
use super::JwtConfig;

/// Authentication service for handling user authentication and tenant context switching
pub struct AuthService {
    /// Database connection pool
    db_pool: PgPool,
    /// JWT configuration
    pub jwt_config: JwtConfig,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(db_pool: PgPool, jwt_config: JwtConfig) -> Self {
        Self {
            db_pool,
            jwt_config,
        }
    }

    /// Generate a JWT token for a user with optional tenant context
    pub fn generate_token(&self, auth_context: &AuthContext) -> Result<String> {
        self.jwt_config.generate_token(auth_context)
    }

    /// Authenticate a user with email and password
    #[allow(unused_variables)]
    pub async fn authenticate(&self, email: &str, password: &str) -> Result<(AuthContext, String)> {
        // NOTE: This is a simplified implementation for demonstration purposes
        // In a real application, you would fetch the user from the database and verify the password
        
        // Create a mock user for testing
        let user = User {
            user_id: 1,
            email: email.to_string(),
            password_hash: "hashed_password".to_string(),
            given_name: "Test".to_string(),
            family_name: "User".to_string(),
            is_active: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        
        // Mock password verification
        if password != "password" {
            return Err(anyhow!("Invalid credentials"));
        }
        
        // Create a mock auth context
        let auth_context = AuthContext {
            user_id: user.user_id,
            tenant_id: None,
            system_roles: vec![SystemRole::Admin],
            tenant_roles: vec![],
        };
        
        // Generate JWT token
        let token = self.jwt_config.generate_token(&auth_context)?;
        
        info!("User authenticated successfully: {}", email);
        Ok((auth_context, token))
    }

    /// Switch tenant context for a user
    #[allow(unused_variables)]
    pub async fn switch_tenant_context(&self, auth_context: &mut AuthContext, tenant_id: Option<i32>) -> Result<String> {
        // NOTE: This is a simplified implementation for demonstration purposes
        // In a real application, you would verify that the user has access to the tenant
        
        if let Some(tid) = tenant_id {
            // Mock tenant access verification
            if auth_context.system_roles.contains(&SystemRole::Admin) {
                // Admin users have access to all tenants
                auth_context.tenant_id = Some(tid);
                auth_context.tenant_roles = vec![SystemRole::TenantSuper];
            } else {
                // For demonstration, assume the user has access to tenant_id 1
                if tid == 1 {
                    auth_context.tenant_id = Some(tid);
                    auth_context.tenant_roles = vec![SystemRole::TenantSuper];
                } else {
                    return Err(anyhow!("User does not have access to the specified tenant"));
                }
            }
        } else {
            // Clear tenant context
            auth_context.tenant_id = None;
            auth_context.tenant_roles = vec![];
        }
        
        // Generate new JWT token with updated context
        let token = self.jwt_config.generate_token(auth_context)?;
        
        debug!("Tenant context switched for user_id: {}, tenant_id: {:?}", auth_context.user_id, tenant_id);
        Ok(token)
    }

    /// Validate a JWT token and extract the auth context
    pub fn validate_token(&self, token: &str) -> Result<AuthContext> {
        let claims = self.jwt_config.validate_token(token)?;
        let auth_context = JwtConfig::claims_to_auth_context(claims);
        
        debug!("Token validated for user_id: {}", auth_context.user_id);
        Ok(auth_context)
    }

    /// Get a user by email
    async fn get_user_by_email(&self, email: &str) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT 
                user_id, email, password_hash, given_name, family_name, 
                is_active, created_at, updated_at
            FROM usr
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;
        
        Ok(user)
    }

    /// Verify a password against a hash
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        // In a real implementation, use argon2 to verify the password
        // For now, we'll just do a simple comparison for demonstration purposes
        Ok(hash == password)
    }

    /// Get a user's system roles
    async fn get_user_system_roles(&self, user_id: i32) -> Result<Vec<SystemRole>> {
        let roles = sqlx::query!(
            r#"
            SELECT r.name
            FROM user_role ur
            JOIN role r ON ur.role_id = r.role_id
            WHERE ur.user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.db_pool)
        .await?;
        
        let system_roles = roles
            .iter()
            .map(|r| SystemRole::from(r.name.as_str()))
            .collect();
        
        Ok(system_roles)
    }

    /// Get a user's tenant roles for a specific tenant
    async fn get_user_tenant_roles(&self, user_id: i32, tenant_id: i32) -> Result<Vec<SystemRole>> {
        let roles = sqlx::query!(
            r#"
            SELECT r.name
            FROM tenant_role tr
            JOIN role r ON tr.role_id = r.role_id
            WHERE tr.user_id = $1 AND tr.tenant_id = $2
            "#,
            user_id,
            tenant_id
        )
        .fetch_all(&self.db_pool)
        .await?;
        
        let tenant_roles = roles
            .iter()
            .map(|r| SystemRole::from(r.name.as_str()))
            .collect();
        
        Ok(tenant_roles)
    }

    /// Check if a user has access to a tenant
    async fn user_has_tenant_access(&self, user_id: i32, tenant_id: i32) -> Result<bool> {
        // Admin users have access to all tenants
        let is_admin = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM user_role ur
            JOIN role r ON ur.role_id = r.role_id
            WHERE ur.user_id = $1 AND r.name = 'ADMIN'
            "#,
            user_id
        )
        .fetch_one(&self.db_pool)
        .await?
        .count
        .unwrap_or(0) > 0;
        
        if is_admin {
            return Ok(true);
        }
        
        // Check if the user is a member of the tenant
        let is_member = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM tenant_member
            WHERE user_id = $1 AND tenant_id = $2
            "#,
            user_id,
            tenant_id
        )
        .fetch_one(&self.db_pool)
        .await?
        .count
        .unwrap_or(0) > 0;
        
        Ok(is_member)
    }
} 