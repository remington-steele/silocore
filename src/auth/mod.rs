mod auth_service;

use anyhow::{Result, anyhow};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;
use time::{Duration, OffsetDateTime};
use tracing::debug;

use crate::model::{AuthContext, SystemRole};

pub use auth_service::AuthService;

/// JWT Claims structure that will be encoded in the token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: i32,
    /// Optional tenant ID for tenant context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<i32>,
    /// System roles assigned to the user
    pub roles: Vec<String>,
    /// Tenant roles assigned to the user (if tenant context is set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_roles: Option<Vec<String>>,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
}

/// Configuration for JWT tokens
pub struct JwtConfig {
    /// Secret key for signing tokens
    encoding_key: EncodingKey,
    /// Key for verifying token signatures
    decoding_key: DecodingKey,
    /// Token expiration time in seconds
    expiration: i64,
    /// Issuer claim value
    issuer: String,
}

impl JwtConfig {
    /// Initialize JWT configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET must be set"))?;
        let expiration = env::var("JWT_EXPIRATION_SECONDS")
            .unwrap_or_else(|_| "86400".to_string()) // Default to 24 hours
            .parse::<i64>()
            .map_err(|_| anyhow!("JWT_EXPIRATION_SECONDS must be a valid number"))?;
        let issuer = env::var("JWT_ISSUER").unwrap_or_else(|_| "silocore".to_string());

        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiration,
            issuer,
        })
    }

    /// Generate a JWT token for a user with optional tenant context
    pub fn generate_token(&self, auth_context: &AuthContext) -> Result<String> {
        let now = OffsetDateTime::now_utc();
        let expiration = now + Duration::seconds(self.expiration);

        // Convert system roles to strings
        let roles: Vec<String> = auth_context.system_roles
            .iter()
            .map(|role| match role {
                SystemRole::Admin => "ADMIN".to_string(),
                SystemRole::Internal => "INTERNAL".to_string(),
                SystemRole::TenantSuper => "TENANT_SUPER".to_string(),
            })
            .collect();

        // Convert tenant roles to strings if tenant context is set
        let tenant_roles = if auth_context.tenant_id.is_some() {
            Some(auth_context.tenant_roles
                .iter()
                .map(|role| match role {
                    SystemRole::Admin => "ADMIN".to_string(),
                    SystemRole::Internal => "INTERNAL".to_string(),
                    SystemRole::TenantSuper => "TENANT_SUPER".to_string(),
                })
                .collect())
        } else {
            None
        };

        let claims = Claims {
            sub: auth_context.user_id,
            tid: auth_context.tenant_id,
            roles,
            tenant_roles,
            iat: now.unix_timestamp(),
            exp: expiration.unix_timestamp(),
            iss: self.issuer.clone(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to generate JWT token: {}", e))?;

        debug!("Generated JWT token for user_id: {}", auth_context.user_id);
        Ok(token)
    }

    /// Validate a JWT token and extract the claims
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Failed to validate JWT token: {}", e))?;
        
        debug!("Validated JWT token for user_id: {}", token_data.claims.sub);
        Ok(token_data.claims)
    }

    /// Convert JWT claims to AuthContext
    pub fn claims_to_auth_context(claims: Claims) -> AuthContext {
        // Convert role strings to SystemRole enum values
        let system_roles = claims.roles
            .iter()
            .map(|role| SystemRole::from(role.as_str()))
            .collect();

        // Convert tenant role strings to SystemRole enum values if present
        let tenant_roles = claims.tenant_roles
            .unwrap_or_default()
            .iter()
            .map(|role| SystemRole::from(role.as_str()))
            .collect();

        AuthContext {
            user_id: claims.sub,
            tenant_id: claims.tid,
            system_roles,
            tenant_roles,
        }
    }

    /// Switch tenant context in an existing AuthContext and generate a new token
    pub fn switch_tenant_context(&self, auth_context: &mut AuthContext, tenant_id: Option<i32>) -> Result<String> {
        // Update the tenant context
        auth_context.tenant_id = tenant_id;
        
        // Clear tenant roles if tenant context is removed
        if tenant_id.is_none() {
            auth_context.tenant_roles.clear();
        }
        
        // Generate a new token with the updated context
        self.generate_token(auth_context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_jwt_token_lifecycle() {
        // Set environment variables for testing
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_for_jwt_token_testing");
            env::set_var("JWT_EXPIRATION_SECONDS", "3600");
            env::set_var("JWT_ISSUER", "test_issuer");
        }

        // Create JWT config
        let jwt_config = JwtConfig::from_env().unwrap();

        // Create test auth context
        let mut auth_context = AuthContext {
            user_id: 123,
            tenant_id: Some(456),
            system_roles: vec![SystemRole::Admin],
            tenant_roles: vec![SystemRole::TenantSuper],
        };

        // Generate token
        let token = jwt_config.generate_token(&auth_context).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = jwt_config.validate_token(&token).unwrap();
        assert_eq!(claims.sub, 123);
        assert_eq!(claims.tid, Some(456));
        assert_eq!(claims.roles.len(), 1);
        assert_eq!(claims.roles[0], "ADMIN");
        assert!(claims.tenant_roles.is_some());
        
        // Store tenant_roles in a separate variable before claims is moved
        let tenant_roles = claims.tenant_roles.clone().unwrap();
        assert_eq!(tenant_roles[0], "TENANT_SUPER");

        // Convert claims back to auth context
        let decoded_context = JwtConfig::claims_to_auth_context(claims);
        assert_eq!(decoded_context.user_id, auth_context.user_id);
        assert_eq!(decoded_context.tenant_id, auth_context.tenant_id);
        assert_eq!(decoded_context.system_roles.len(), auth_context.system_roles.len());
        assert_eq!(decoded_context.tenant_roles.len(), auth_context.tenant_roles.len());

        // Test switching tenant context
        auth_context.tenant_id = None;
        let new_token = jwt_config.switch_tenant_context(&mut auth_context, None).unwrap();
        let new_claims = jwt_config.validate_token(&new_token).unwrap();
        assert_eq!(new_claims.tid, None);
        assert!(new_claims.tenant_roles.is_none() || new_claims.tenant_roles.unwrap().is_empty());
    }
} 