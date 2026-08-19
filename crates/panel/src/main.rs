mod api;
mod cli;
mod config;
mod db;
mod dto;
mod service;

use axum::Router;
use config::Config;
use db::init::{init_db, init_pg, is_postgres_url};
use db::pg_repo::PgRepository;
use db::repo::Repository;
use db::sqlite_repo::SqliteRepository;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::load();

    // Recovery commands use the same backend initialization and migrations as
    // the server, then exit before binding a port or starting background jobs.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command) = args.first() {
        match command.as_str() {
            "reset-admin-password" => {
                let db = open_database(&config).await;
                let username = args.get(1).map(String::as_str).unwrap_or("admin");
                std::process::exit(cli::reset_admin_password(db, username).await);
            }
            "--help" | "-h" | "help" => {
                print!("{}", cli::USAGE);
                std::process::exit(0);
            }
            other => {
                eprintln!("未知命令：{other}\n");
                print!("{}", cli::USAGE);
                std::process::exit(2);
            }
        }
    }

    let db = open_database(&config).await;

    // v0.4.10 PR3: seed the app_settings row from REGISTRATION_ENABLED on the
    // very first boot. insert_settings_if_absent is a no-op once the row
    // exists, so the env var can NEVER re-enable registration after an admin
    // turns it off — only the admin PUT endpoint mutates the row afterwards.
    // This runs through the Repository trait so SQLite + PG share one path.
    db.insert_settings_if_absent(config.registration_enabled, 1, &[1])
        .await
        .expect("Failed to seed app settings");

    // Build the SPA fallback: ServeDir handles static assets, and any unknown
    // path falls back to index.html so client-side routing works.
    let public_dir = ServeDir::new(&config.public_dir)
        .fallback(ServeFile::new(format!("{}/index.html", config.public_dir)));

    // v0.3.9: CORS is opt-in via CORS_ORIGINS. The standard deployment is
    // same-origin (panel serves the built frontend itself), which needs NO
    // CORS layer at all. Only when the frontend runs cross-origin (Vite dev
    // server on :5173, or a split frontend/backend deploy) does the operator
    // set CORS_ORIGINS=http://localhost:5173,... and we add a restrictive
    // layer limited to exactly those origins. This replaces the old
    // `CorsLayer::permissive()`, which let ANY origin call the admin API.
    let mut app = Router::new()
        .nest("/api/v1", api::routes())
        .fallback_service(public_dir);
    if !config.cors_origins.is_empty() {
        let origins: Vec<axum::http::HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        tracing::info!(
            "CORS enabled for origins: {} (same-origin requests are unaffected)",
            config.cors_origins.join(", ")
        );
        app = app.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_headers(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any),
        );
    } else {
        tracing::info!(
            "CORS disabled (same-origin deployment). Set CORS_ORIGINS for cross-origin dev/split deploy."
        );
    }
    // Security response headers (CSP, X-Frame-Options, X-Content-Type-Options,
    // Referrer-Policy, Permissions-Policy) on every response — API + static SPA
    // assets. HSTS is intentionally NOT set here (it belongs to the HTTPS/proxy
    // layer; the panel may listen on plain HTTP behind Caddy). See
    // api::security_headers for the exact policy.
    let app = api::security_headers::apply_security_headers(app);
    let state = api::AppState {
        db: db.clone(),
        config: config.clone(),
        release_cache: api::system::ReleaseCache::new(),
        node_connections: api::ws::NodeConnections::new(),
        diagnose: api::diagnose::DiagnoseRegistry::new(),
        geoip_in_flight: std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashSet::new(),
        )),
    };

    // v1.2.0: scheduled rule restarts. Shares the AppState (and therefore the
    // same node WS registry) with the HTTP handlers, so a scheduled restart goes
    // out over exactly the same control channel as a manual one.
    service::auto_restart::spawn(state.clone());

    // v1.2.0: node offline/recovery alerting. Runs unconditionally — it tracks
    // state even when notifications are disabled, so turning them on later
    // doesn't immediately fire for outages that started before.
    service::node_watch::spawn(state.clone());

    // v1.2.0: traffic-history retention. The history table has no FK, so this
    // sweeper is the only thing that ever deletes its rows.
    service::history_prune::spawn(state.clone());

    // Explicit opt-in recurring billing for monthly plans. The repository
    // rechecks expiry and locks each user, so multiple panel instances cannot
    // double-charge the same cycle.
    service::monthly_renewal::spawn(state.clone());

    let app = app.with_state(state);

    let addr: SocketAddr = config.listen.parse().expect("Invalid listen address");
    tracing::info!(
        "RelayPanel listening on {} (public dir: {})",
        addr,
        config.public_dir
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    // Attach the TCP peer address to every request. Status reporting uses it
    // as the direct-connection fallback when no reverse proxy supplied a
    // forwarded client address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Open the configured backend, run migrations, and return the repository.
/// Shared by the HTTP server and CLI recovery paths so they cannot point at
/// different databases or apply different schema initialization.
async fn open_database(config: &Config) -> Arc<dyn Repository> {
    // v0.4.3: backend is chosen at startup by the database_url prefix and is
    // fixed for the process lifetime — NO runtime switching, NO fallback. If
    // the URL is a PostgreSQL DSN, we init PG; anything else (including the
    // default SQLite file path) inits SQLite.
    //
    // Fail-fast contract: a configured PG backend that can't connect MUST
    // terminate startup. Falling back to SQLite would silently write data
    // locally while the user believes it's in PG — strictly worse than a crash.
    if is_postgres_url(&config.database_path) {
        tracing::info!("database backend: PostgreSQL");
        let pool = init_pg(&config.database_path)
            .await
            .expect("Failed to initialize PostgreSQL database");
        Arc::new(PgRepository::new(pool))
    } else {
        if config.database_path == "sqlite::memory:" || config.database_path.is_empty() {
            tracing::info!("database backend: SQLite (in-memory / default)");
        } else {
            tracing::info!("database backend: SQLite ({})", config.database_path);
        }
        let pool = init_db(&config.database_path)
            .await
            .expect("Failed to initialize SQLite database");
        Arc::new(SqliteRepository::new(pool))
    }
}
