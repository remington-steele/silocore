use anyhow::{Result, anyhow};
use sqlx::PgPool;
use tracing::{debug, info, error};
use time::OffsetDateTime;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Error as PasswordHashError
    },
    Argon2
};

use crate::model::{AuthContext, SystemRole, User, Role, UserRole, TenantMember, TenantRole};
use crate::db;
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

    /// Hash a password using Argon2
    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Password hashing error: {}", e))?
            .to_string();
        Ok(password_hash)
    }

    /// Verify a password against a hash using Argon2
    pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| anyhow!("Password hash parsing error: {}", e))?;
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
        Ok(result)
    }

    /// Authenticate a user with email and password
    pub async fn authenticate(&self, email: &str, password: &str) -> Result<(AuthContext, String)> {
        // Fetch user from database
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM core.usr WHERE email = $1 AND is_active = TRUE"
        )
        .bind(email)
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("Invalid credentials"))?;
        
        // Verify password
        if !Self::verify_password(password, &user.password_hash)? {
            error!("Password verification failed for user: {}", email);
            return Err(anyhow!("Invalid credentials"));
        }
        
        // Fetch user's system roles
        let system_roles = self.get_user_system_roles(user.user_id).await?;
        
        // Create auth context without tenant context
        let auth_context = AuthContext {
            user_id: user.user_id,
            tenant_id: None,
            system_roles,
            tenant_roles: vec![],
        };
        
        // Generate JWT token
        let token = self.jwt_config.generate_token(&auth_context)?;
        
        info!("User authenticated successfully: {}", email);
        Ok((auth_context, token))
    }

    /// Get a user's system roles
    async fn get_user_system_roles(&self, user_id: i32) -> Result<Vec<SystemRole>> {
        // Clear tenant context to ensure we can access all roles
        db::clear_tenant_context(&self.db_pool).await?;
        
        // Fetch user's system roles from database
        let roles: Vec<Role> = sqlx::query_as::<_, Role>(
            "SELECT r.* FROM core.role r
             JOIN core.user_role ur ON r.role_id = ur.role_id
             WHERE ur.user_id = $1"
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        
        // Convert role names to SystemRole enum values
        let system_roles = roles.iter()
            .map(|role| SystemRole::from(role.name.as_str()))
            .collect();
        
        Ok(system_roles)
    }

    /// Get a user's tenant roles for a specific tenant
    async fn get_user_tenant_roles(&self, user_id: i32, tenant_id: i32) -> Result<Vec<SystemRole>> {
        // Set tenant context to ensure we only see roles for this tenant
        db::set_tenant_context(&self.db_pool, tenant_id).await?;
        
        // Fetch user's tenant roles from database
        let roles: Vec<Role> = sqlx::query_as::<_, Role>(
            "SELECT r.* FROM core.role r
             JOIN core.tenant_role tr ON r.role_id = tr.role_id
             WHERE tr.user_id = $1 AND tr.tenant_id = $2"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.db_pool)
        .await?;
        
        // Convert role names to SystemRole enum values
        let tenant_roles = roles.iter()
            .map(|role| SystemRole::from(role.name.as_str()))
            .collect();
        
        Ok(tenant_roles)
    }

    /// Check if a user is a member of a tenant
    async fn is_tenant_member(&self, user_id: i32, tenant_id: i32) -> Result<bool> {
        // Clear tenant context to ensure we can access all tenant memberships
        db::clear_tenant_context(&self.db_pool).await?;
        
        // Check if user is a member of the tenant
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM core.tenant_member 
             WHERE user_id = $1 AND tenant_id = $2"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.db_pool)
        .await?;
        
        Ok(count > 0)
    }

    /// Switch tenant context for a user
    pub async fn switch_tenant_context(&self, auth_context: &mut AuthContext, tenant_id: Option<i32>) -> Result<String> {
        if let Some(tid) = tenant_id {
            // Check if tenant exists
            let tenant_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM core.tenant WHERE tenant_id = $1)"
            )
            .bind(tid)
            .fetch_one(&self.db_pool)
            .await?;
            
            if !tenant_exists {
                return Err(anyhow!("Tenant does not exist"));
            }
            
            // Check if user has access to the tenant
            let is_admin = auth_context.system_roles.contains(&SystemRole::Admin);
            
            if !is_admin && !self.is_tenant_member(auth_context.user_id, tid).await? {
                return Err(anyhow!("User does not have access to the specified tenant"));
            }
            
            // Get user's tenant roles
            let tenant_roles = self.get_user_tenant_roles(auth_context.user_id, tid).await?;
            
            // Update auth context
            auth_context.tenant_id = Some(tid);
            auth_context.tenant_roles = tenant_roles;
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
    
    /// Register a new user
    pub async fn register_user(&self, email: &str, password: &str, given_name: &str, family_name: &str) -> Result<User> {
        // Hash the password
        let password_hash = Self::hash_password(password)?;
        
        // Insert the new user
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO core.usr (email, password_hash, given_name, family_name, is_active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, TRUE, $5, $5)
             RETURNING *"
        )
        .bind(email)
        .bind(password_hash)
        .bind(given_name)
        .bind(family_name)
        .bind(OffsetDateTime::now_utc())
        .fetch_one(&self.db_pool)
        .await?;
        
        info!("New user registered: {}", email);
        Ok(user)
    }
    
    /// Assign a system role to a user
    pub async fn assign_system_role(&self, user_id: i32, role_name: &str) -> Result<()> {
        // Get role ID from name
        let role_id: i32 = sqlx::query_scalar(
            "SELECT role_id FROM core.role WHERE name = $1"
        )
        .bind(role_name)
        .fetch_one(&self.db_pool)
        .await?;
        
        // Insert user role
        sqlx::query(
            "INSERT INTO core.user_role (user_id, role_id, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id, role_id) DO NOTHING"
        )
        .bind(user_id)
        .bind(role_id)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.db_pool)
        .await?;
        
        info!("System role {} assigned to user_id: {}", role_name, user_id);
        Ok(())
    }
    
    /// Add a user to a tenant
    pub async fn add_user_to_tenant(&self, user_id: i32, tenant_id: i32) -> Result<()> {
        // Insert tenant member
        sqlx::query(
            "INSERT INTO core.tenant_member (tenant_id, user_id, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, user_id) DO NOTHING"
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.db_pool)
        .await?;
        
        info!("User_id: {} added to tenant_id: {}", user_id, tenant_id);
        Ok(())
    }
    
    /// Assign a tenant role to a user
    pub async fn assign_tenant_role(&self, user_id: i32, tenant_id: i32, role_name: &str) -> Result<()> {
        // Get role ID from name
        let role_id: i32 = sqlx::query_scalar(
            "SELECT role_id FROM core.role WHERE name = $1"
        )
        .bind(role_name)
        .fetch_one(&self.db_pool)
        .await?;
        
        // Insert tenant role
        sqlx::query(
            "INSERT INTO core.tenant_role (tenant_id, user_id, role_id, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING"
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role_id)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.db_pool)
        .await?;
        
        info!("Tenant role {} assigned to user_id: {} for tenant_id: {}", role_name, user_id, tenant_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::env;
    use dotenv::dotenv;

    async fn setup_test_db() -> PgPool {
        dotenv().ok();
        
        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for tests");
        
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to create database connection pool");
        
        // Run migrations to ensure schema is up to date
        sqlx::migrate!("./sql/migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");
        
        pool
    }
    
    #[tokio::test]
    async fn test_password_hashing() {
        let password = "test_password";
        let hash = AuthService::hash_password(password).unwrap();
        
        // Verify the password against the hash
        let result = AuthService::verify_password(password, &hash).unwrap();
        assert!(result);
        
        // Verify an incorrect password fails
        let result = AuthService::verify_password("wrong_password", &hash).unwrap();
        assert!(!result);
    }
    
    #[tokio::test]
    async fn test_user_registration_and_authentication() {
        let pool = setup_test_db().await;
        let jwt_config = JwtConfig::from_env().unwrap();
        let auth_service = AuthService::new(pool.clone(), jwt_config);
        
        // Generate a unique email for this test
        let email = format!("test_user_{}@example.com", time::OffsetDateTime::now_utc().unix_timestamp());
        
        // Register a new user
        let user = auth_service.register_user(
            &email,
            "test_password",
            "Test",
            "User"
        ).await.unwrap();
        
        assert_eq!(user.email, email);
        assert_eq!(user.given_name, "Test");
        assert_eq!(user.family_name, "User");
        assert!(user.is_active);
        
        // Authenticate the user
        let result = auth_service.authenticate(&email, "test_password").await;
        assert!(result.is_ok());
        
        let (auth_context, token) = result.unwrap();
        assert_eq!(auth_context.user_id, user.user_id);
        assert!(auth_context.tenant_id.is_none());
        assert!(auth_context.system_roles.is_empty());
        assert!(auth_context.tenant_roles.is_empty());
        
        // Verify token
        let validated_context = auth_service.validate_token(&token).unwrap();
        assert_eq!(validated_context.user_id, user.user_id);
        
        // Test authentication with wrong password
        let result = auth_service.authenticate(&email, "wrong_password").await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_system_roles() {
        let pool = setup_test_db().await;
        let jwt_config = JwtConfig::from_env().unwrap();
        let auth_service = AuthService::new(pool.clone(), jwt_config);
        
        // Generate a unique email for this test
        let email = format!("test_admin_{}@example.com", time::OffsetDateTime::now_utc().unix_timestamp());
        
        // Register a new user
        let user = auth_service.register_user(
            &email,
            "test_password",
            "Admin",
            "User"
        ).await.unwrap();
        
        // Assign admin role
        auth_service.assign_system_role(user.user_id, "ADMIN").await.unwrap();
        
        // Authenticate the user
        let (auth_context, _) = auth_service.authenticate(&email, "test_password").await.unwrap();
        
        // Verify the user has the admin role
        assert!(auth_context.system_roles.contains(&SystemRole::Admin));
    }
    
    #[tokio::test]
    async fn test_tenant_context_switching() {
        let pool = setup_test_db().await;
        let jwt_config = JwtConfig::from_env().unwrap();
        let auth_service = AuthService::new(pool.clone(), jwt_config);
        
        // Create a test tenant
        let tenant_id: i32 = sqlx::query_scalar(
            "INSERT INTO core.tenant (name, status, tier, created_at, updated_at)
             VALUES ($1, 'active', 'gold', $2, $2)
             RETURNING tenant_id"
        )
        .bind(format!("Test Tenant {}", time::OffsetDateTime::now_utc().unix_timestamp()))
        .bind(time::OffsetDateTime::now_utc())
        .fetch_one(&pool)
        .await
        .unwrap();
        
        // Generate a unique email for this test
        let email = format!("test_tenant_{}@example.com", time::OffsetDateTime::now_utc().unix_timestamp());
        
        // Register a new user
        let user = auth_service.register_user(
            &email,
            "test_password",
            "Tenant",
            "User"
        ).await.unwrap();
        
        // Add user to tenant
        auth_service.add_user_to_tenant(user.user_id, tenant_id).await.unwrap();
        
        // Assign tenant super role
        auth_service.assign_tenant_role(user.user_id, tenant_id, "TENANT_SUPER").await.unwrap();
        
        // Authenticate the user
        let (mut auth_context, _) = auth_service.authenticate(&email, "test_password").await.unwrap();
        
        // Switch to tenant context
        let token = auth_service.switch_tenant_context(&mut auth_context, Some(tenant_id)).await.unwrap();
        
        // Verify tenant context
        assert_eq!(auth_context.tenant_id, Some(tenant_id));
        assert!(auth_context.tenant_roles.contains(&SystemRole::TenantSuper));
        
        // Validate token
        let validated_context = auth_service.validate_token(&token).unwrap();
        assert_eq!(validated_context.tenant_id, Some(tenant_id));
        assert!(validated_context.tenant_roles.contains(&SystemRole::TenantSuper));
        
        // Clear tenant context
        let token = auth_service.switch_tenant_context(&mut auth_context, None).await.unwrap();
        
        // Verify tenant context is cleared
        assert!(auth_context.tenant_id.is_none());
        assert!(auth_context.tenant_roles.is_empty());
    }
}