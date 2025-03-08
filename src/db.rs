use anyhow::Result;
use sqlx::{postgres::{PgPoolOptions, PgConnectOptions}, PgPool, Postgres, Transaction, Connection, PgConnection};
use std::{env, str::FromStr};
use tracing::info;

/// Initialize the database connection pool for the application
pub async fn init_pool() -> Result<PgPool> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    info!("Initializing application database connection pool");
    
    // Parse the connection string
    let options = PgConnectOptions::from_str(&database_url)?;
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    
    info!("Application database connection pool initialized");
    Ok(pool)
}

/// Create a single admin database connection for migrations
pub async fn create_admin_connection() -> Result<PgConnection> {
    let database_admin_url = env::var("DATABASE_ADMIN_URL")
        .expect("DATABASE_ADMIN_URL must be set for running migrations");
    
    info!("Creating admin database connection for migrations");
    
    // Parse the connection string
    let options = PgConnectOptions::from_str(&database_admin_url)?;
    
    let conn = PgConnection::connect_with(&options).await?;
    
    info!("Admin database connection established");
    Ok(conn)
}

/// Set the tenant context for the current database session
pub async fn set_tenant_context(pool: &PgPool, tenant_id: i32) -> Result<()> {
    sqlx::query("SELECT set_tenant_context($1)")
        .bind(tenant_id)
        .execute(pool)
        .await?;
    
    Ok(())
}

/// Clear the tenant context for the current database session (for admin operations)
pub async fn clear_tenant_context(pool: &PgPool) -> Result<()> {
    sqlx::query("SELECT clear_tenant_context()")
        .execute(pool)
        .await?;
    
    Ok(())
}

/// Set the tenant context for a transaction
pub async fn set_transaction_tenant_context(tx: &mut Transaction<'_, Postgres>, tenant_id: i32) -> Result<()> {
    sqlx::query("SELECT set_tenant_context($1)")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    
    Ok(())
}

/// Clear the tenant context for a transaction (for admin operations)
pub async fn clear_transaction_tenant_context(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("SELECT clear_tenant_context()")
        .execute(&mut **tx)
        .await?;
    
    Ok(())
} 