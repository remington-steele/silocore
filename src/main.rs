use anyhow::Result;
use dotenv::dotenv;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use sqlx::Connection;
use time::OffsetDateTime;

mod db;
mod model;
mod auth;

use model::{AuthContext, SystemRole};
use auth::{JwtConfig, AuthService};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize environment variables from .env file
    dotenv().ok();

    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting application");

    // Create a single admin connection for migrations
    info!("Creating admin connection for database migrations");
    let mut admin_conn = db::create_admin_connection().await?;

    // Run migrations using admin connection
    info!("Running database migrations with admin privileges");
    sqlx::migrate!("./sql/migrations").run(&mut admin_conn).await?;
    info!("Migrations completed successfully");
    
    // Close admin connection after migrations are complete
    info!("Closing admin database connection");
    let _ = admin_conn.close().await;

    // Initialize regular application database connection pool
    let pool = db::init_pool().await?;
    info!("Application database connection initialized");

    // Initialize JWT configuration
    info!("Initializing JWT configuration");
    let jwt_config = JwtConfig::from_env()?;
    
    // Initialize authentication service
    let auth_service = AuthService::new(pool.clone(), jwt_config);
    info!("Authentication service initialized");
    
    // Create a test tenant if it doesn't exist
    db::clear_tenant_context(&pool).await?;
    
    let tenant_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM core.tenant WHERE name = 'Demo Tenant')"
    )
    .fetch_one(&pool)
    .await?;
    
    let tenant_id = if !tenant_exists {
        info!("Creating demo tenant");
        let now = OffsetDateTime::now_utc();
        
        sqlx::query_scalar(
            "INSERT INTO core.tenant (name, status, tier, created_at, updated_at)
             VALUES ('Demo Tenant', 'active', 'gold', $1, $1)
             RETURNING tenant_id"
        )
        .bind(now)
        .fetch_one(&pool)
        .await?
    } else {
        info!("Demo tenant already exists");
        sqlx::query_scalar("SELECT tenant_id FROM core.tenant WHERE name = 'Demo Tenant'")
            .fetch_one(&pool)
            .await?
    };
    
    info!("Demo tenant ID: {}", tenant_id);
    
    // Create a test admin user if it doesn't exist
    let admin_email = "admin@example.com";
    
    let admin_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM core.usr WHERE email = $1)"
    )
    .bind(admin_email)
    .fetch_one(&pool)
    .await?;
    
    let admin_id = if !admin_exists {
        info!("Creating admin user");
        
        // Register the admin user
        let admin = auth_service.register_user(
            admin_email,
            "admin_password",
            "Admin",
            "User"
        ).await?;
        
        // Assign admin role
        auth_service.assign_system_role(admin.user_id, "ADMIN").await?;
        
        admin.user_id
    } else {
        info!("Admin user already exists");
        sqlx::query_scalar("SELECT user_id FROM core.usr WHERE email = $1")
            .bind(admin_email)
            .fetch_one(&pool)
            .await?
    };
    
    info!("Admin user ID: {}", admin_id);
    
    // Create a test tenant user if it doesn't exist
    let tenant_user_email = "tenant_user@example.com";
    
    let tenant_user_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM core.usr WHERE email = $1)"
    )
    .bind(tenant_user_email)
    .fetch_one(&pool)
    .await?;
    
    let tenant_user_id = if !tenant_user_exists {
        info!("Creating tenant user");
        
        // Register the tenant user
        let tenant_user = auth_service.register_user(
            tenant_user_email,
            "tenant_password",
            "Tenant",
            "User"
        ).await?;
        
        // Add user to tenant
        auth_service.add_user_to_tenant(tenant_user.user_id, tenant_id).await?;
        
        // Assign tenant super role
        auth_service.assign_tenant_role(tenant_user.user_id, tenant_id, "TENANT_SUPER").await?;
        
        tenant_user.user_id
    } else {
        info!("Tenant user already exists");
        let user_id: i32 = sqlx::query_scalar("SELECT user_id FROM core.usr WHERE email = $1")
            .bind(tenant_user_email)
            .fetch_one(&pool)
            .await?;
            
        // Ensure user is a member of the tenant
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM core.tenant_member WHERE user_id = $1 AND tenant_id = $2)"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&pool)
        .await?;
        
        if !is_member {
            info!("Adding tenant user to tenant");
            auth_service.add_user_to_tenant(user_id, tenant_id).await?;
        }
        
        // Ensure user has tenant super role
        let has_role: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM core.tenant_role tr
                JOIN core.role r ON tr.role_id = r.role_id
                WHERE tr.user_id = $1 AND tr.tenant_id = $2 AND r.name = 'TENANT_SUPER'
            )"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&pool)
        .await?;
        
        if !has_role {
            info!("Assigning tenant super role to tenant user");
            auth_service.assign_tenant_role(user_id, tenant_id, "TENANT_SUPER").await?;
        }
        
        user_id
    };
    
    info!("Tenant user ID: {}", tenant_user_id);
    
    // Authenticate admin user
    info!("Authenticating admin user");
    let (mut admin_context, admin_token) = auth_service.authenticate(admin_email, "admin_password").await?;
    info!("Admin user authenticated successfully");
    info!("Admin token: {}", admin_token);
    info!("Admin context: {:?}", admin_context);
    
    // Switch admin to tenant context
    info!("Switching admin to tenant context");
    let admin_tenant_token = auth_service.switch_tenant_context(&mut admin_context, Some(tenant_id)).await?;
    info!("Admin switched to tenant context successfully");
    info!("Admin tenant token: {}", admin_tenant_token);
    info!("Admin tenant context: {:?}", admin_context);
    
    // Authenticate tenant user
    info!("Authenticating tenant user");
    let (mut tenant_user_context, tenant_user_token) = auth_service.authenticate(tenant_user_email, "tenant_password").await?;
    info!("Tenant user authenticated successfully");
    info!("Tenant user token: {}", tenant_user_token);
    info!("Tenant user context: {:?}", tenant_user_context);
    
    // Switch tenant user to tenant context
    info!("Switching tenant user to tenant context");
    let tenant_user_tenant_token = auth_service.switch_tenant_context(&mut tenant_user_context, Some(tenant_id)).await?;
    info!("Tenant user switched to tenant context successfully");
    info!("Tenant user tenant token: {}", tenant_user_tenant_token);
    info!("Tenant user tenant context: {:?}", tenant_user_context);

    info!("Application initialized successfully");
    Ok(())
}
