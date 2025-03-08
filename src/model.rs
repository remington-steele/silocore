use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub tenant_id: i32,
    pub name: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub user_id: i32,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub role_id: i32,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserRole {
    pub user_id: i32,
    pub role_id: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct TenantMember {
    pub tenant_id: i32,
    pub user_id: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct TenantRole {
    pub tenant_id: i32,
    pub user_id: i32,
    pub role_id: i32,
    pub created_at: OffsetDateTime,
}

// Enum for system roles
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemRole {
    Admin,
    Internal,
    TenantSuper,
}

impl From<&str> for SystemRole {
    fn from(s: &str) -> Self {
        match s {
            "ADMIN" => SystemRole::Admin,
            "INTERNAL" => SystemRole::Internal,
            "TENANT_SUPER" => SystemRole::TenantSuper,
            _ => panic!("Invalid system role: {}", s),
        }
    }
}

impl From<SystemRole> for String {
    fn from(role: SystemRole) -> Self {
        match role {
            SystemRole::Admin => "ADMIN".to_string(),
            SystemRole::Internal => "INTERNAL".to_string(),
            SystemRole::TenantSuper => "TENANT_SUPER".to_string(),
        }
    }
}

// Auth context for a user
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthContext {
    pub user_id: i32,
    pub tenant_id: Option<i32>,
    pub system_roles: Vec<SystemRole>,
    pub tenant_roles: Vec<SystemRole>,
} 