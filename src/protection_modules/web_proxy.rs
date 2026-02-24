// // src/protection_modules/web_proxy.rs
// use crate::communication::ServerCommunicator;
// use crate::policy_constants::*;
// use crate::policy_engine::PolicyEngine;
// use crate::protection_modules::dto::WebLog;
// use crate::protection_modules::ProtectionModule;
// use hyper::upgrade::Upgraded;
// use log::{debug, error, info, trace, warn};
// use rcgen::{Certificate, CertificateParams, KeyPair};
// use std::any::Any;
// use std::error::Error;
// use std::ffi::c_void;
// use std::path::{Path, PathBuf};
// use std::ptr;
// use std::sync::Arc;
// use tokio::sync::RwLock;
// use tokio_rustls::{TlsAcceptor, TlsConnector};

// // Windows API imports
// use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
// use windows_sys::Win32::Security::Cryptography::{
//     CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore,
//     CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_ID,
//     CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
// };
// use windows_sys::Win32::Security::{
//     AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
//     SE_PRIVILEGE_ENABLED, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
// };
// use windows_sys::Win32::System::Registry::{
//     RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
// };
// use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// // HTTP imports
// use hyper::server::conn::Http;
// use hyper::service::service_fn;
// use hyper::{Body, Client, Method, Request, Response, StatusCode, Uri};
// use rustls::{Certificate as RustlsCertificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
// use tokio::net::TcpListener;
// use time::{Duration, OffsetDateTime};

// type ProxyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// // Global buffer for web logs
// lazy_static::lazy_static! {
//     static ref WEB_LOG_BUFFER: std::sync::Mutex<Vec<WebLog>> = std::sync::Mutex::new(Vec::new());
// }

// // Certificate cache for performance
// lazy_static::lazy_static! {
//     static ref CERT_CACHE: tokio::sync::Mutex<std::collections::HashMap<String, (Vec<u8>, Vec<u8>)>> = 
//         tokio::sync::Mutex::new(std::collections::HashMap::new());
// }

// // ===== WEB PROXY PROTECTION MODULE =====
// pub struct WebProxyProtection {
//     proxy_is_active: bool,
//     policy_engine: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
//     server_handle: Option<tokio::task::JoinHandle<()>>,
//     certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
// }

// impl WebProxyProtection {
//     // === ADMIN PRIVILEGE CHECK ===
//     fn is_running_as_admin() -> bool {
//         unsafe {
//             let mut token_handle: HANDLE = 0;
//             let current_process = GetCurrentProcess();

//             if OpenProcessToken(current_process, 0x0008, &mut token_handle) != TRUE {
//                 return false;
//             }

//             let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
//             let mut return_length = 0;

//             let result = GetTokenInformation(
//                 token_handle,
//                 windows_sys::Win32::Security::TokenElevation,
//                 &mut elevation as *mut _ as *mut c_void,
//                 std::mem::size_of::<TOKEN_ELEVATION>() as u32,
//                 &mut return_length,
//             );

//             CloseHandle(token_handle);

//             result == TRUE && elevation.TokenIsElevated != 0
//         }
//     }

//     fn enable_privilege(privilege: &str) -> bool {
//         unsafe {
//             let mut token_handle: HANDLE = 0;
//             let current_process = GetCurrentProcess();

//             if OpenProcessToken(current_process, 0x0020 | 0x0008, &mut token_handle) != TRUE {
//                 return false;
//             }

//             let mut luid = std::mem::zeroed();
//             let privilege_wide: Vec<u16> =
//                 privilege.encode_utf16().chain(std::iter::once(0)).collect();

//             if LookupPrivilegeValueW(std::ptr::null(), privilege_wide.as_ptr(), &mut luid) != TRUE {
//                 CloseHandle(token_handle);
//                 return false;
//             }

//             let mut tp = TOKEN_PRIVILEGES {
//                 PrivilegeCount: 1,
//                 Privileges: [LUID_AND_ATTRIBUTES {
//                     Luid: luid,
//                     Attributes: SE_PRIVILEGE_ENABLED,
//                 }],
//             };

//             let result = AdjustTokenPrivileges(
//                 token_handle,
//                 0,
//                 &mut tp,
//                 0,
//                 std::ptr::null_mut(),
//                 std::ptr::null_mut(),
//             ) == TRUE;

//             CloseHandle(token_handle);
//             result
//         }
//     }

// // Replace old install_ca_certificate_strict with this async version
// async fn install_ca_certificate_strict(cert_der: &[u8]) -> ProxyResult<()> {
//     use tokio::task;
//     use tokio::time::{sleep, Duration as TokioDuration};

//     info!("🔐 FORCING DLP Root CA installation with enhanced debugging...");

//     // Run diagnostics first (blocking – run in spawn_blocking)
//     if let Err(e) = task::spawn_blocking(|| Self::diagnose_certificate_issue()).await? {
//         warn!("Pre-installation diagnostics failed: {}", e);
//     }

//     Self::enable_all_certificate_privileges();

//     let mut installed_locations = Vec::new();
//     let mut failed_locations = Vec::new();

//     // Try ALL possible certificate stores
//     let store_attempts = [
//         (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, "Root", "Local Machine - Root"),
//         (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, "CA", "Local Machine - CA"),
//         (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, "TrustedPublisher", "Local Machine - Trusted Publisher"),
//         (CERT_SYSTEM_STORE_CURRENT_USER_ID, "Root", "Current User - Root"),
//         (CERT_SYSTEM_STORE_CURRENT_USER_ID, "CA", "Current User - CA"),
//         (CERT_SYSTEM_STORE_CURRENT_USER_ID, "TrustedPublisher", "Current User - Trusted Publisher"),
//     ];

//     for (location, store_name, description) in &store_attempts {
//         // clone for move into blocking closure
//         let cert_clone = cert_der.to_vec();
//         let store_name_owned = store_name.to_string();
//         let desc_owned = description.to_string();
//         let loc = *location;

//         info!("  Attempting install to {}...", description);
//         let res = task::spawn_blocking(move || {
//             WebProxyProtection::force_install_to_store_verbose(&cert_clone, loc, &store_name_owned, &desc_owned)
//         }).await;

//         match res {
//             Ok(Ok(())) => {
//                 info!("🎉 Successfully installed to: {}", description);
//                 installed_locations.push(description.to_string());
//             }
//             Ok(Err(e)) => {
//                 error!("❌ Failed to install to {}: {}", description, e);
//                 failed_locations.push(format!("{}: {}", description, e));
//             }
//             Err(join_err) => {
//                 error!("❌ Thread join error while installing to {}: {}", description, join_err);
//                 failed_locations.push(format!("{}: join error: {}", description, join_err));
//             }
//         }

//         // Small async delay between attempts
//         sleep(TokioDuration::from_millis(100)).await;
//     }

//     // Additional method: Use certutil command line (blocking)
//     info!("🛠️ Trying certutil installation method...");
//     match Self::install_via_certutil_enhanced(cert_der).await {
//         Ok(()) => {
//             info!("✅ Certutil installation successful");
//             installed_locations.push("certutil".to_string());
//         }
//         Err(e) => {
//             error!("Certutil installation failed: {}", e);
//             failed_locations.push(format!("certutil: {}", e));
//         }
//     }

//     if installed_locations.is_empty() {
//         error!("❌ ALL certificate installation methods failed: {:?}", failed_locations);
//         Self::export_ca_for_manual_install(cert_der)?;
//         return Err(format!("Complete installation failure: {:?}", failed_locations).into());
//     }

//     info!("✅ Certificate installed to {} location(s): {:?}", installed_locations.len(), installed_locations);

//     // Verify installation (diagnostics)
//     if let Err(e) = task::spawn_blocking(|| Self::diagnose_certificate_issue()).await? {
//         error!("Post-installation verification failed: {}", e);
//     }

//     info!("🔓 Certificate installation completed");
//     Ok(())
// }


// fn force_install_to_store_verbose(
//     cert_der: &[u8], 
//     store_location: u32, 
//     store_name: &str,
//     description: &str,
// ) -> ProxyResult<()> {
//     let store_name_wide: Vec<u16> = store_name.encode_utf16().chain(std::iter::once(0)).collect();

//     unsafe {
//         info!("  Opening store: {}...", description);
//         let store_handle = CertOpenStore(
//             CERT_STORE_PROV_SYSTEM_W,
//             0,
//             0,
//             store_location,
//             store_name_wide.as_ptr() as *const c_void,
//         );

//         if store_handle.is_null() {
//             let error_code = windows_sys::Win32::Foundation::GetLastError();
//             return Err(format!("Failed to open store {} (error: {})", description,error_code).into());
//         }

//         info!("  Adding certificate to {}...", description);
//         let result = CertAddEncodedCertificateToStore(
//             store_handle,
//             1, // X509_ASN_ENCODING
//             cert_der.as_ptr(),
//             cert_der.len() as u32,
//             CERT_STORE_ADD_REPLACE_EXISTING,
//             std::ptr::null_mut(),
//         );

//         let close_result = CertCloseStore(store_handle, 0);

//         if result != TRUE {
//             let error_code = windows_sys::Win32::Foundation::GetLastError();
//             return Err(format!("Failed to add certificate to {} (error: {})", description, error_code).into());
//         }

//         if close_result != TRUE {
//             warn!("Warning: Failed to properly close certificate store {}", description);
//         }

//         info!("  ✅ Successfully installed to {}", description);
//         Ok(())
//     }
// }

// async fn install_via_certutil_enhanced(cert_der: &[u8]) -> ProxyResult<()> {
//     use tempfile::NamedTempFile;
//     use tokio::task;
//     use std::io::Write;

//     // Create temp file synchronously (this is cheap)
//     let mut temp_file = NamedTempFile::new()?;
//     temp_file.write_all(cert_der)?;
//     let temp_path_owned = temp_file.path().to_path_buf();

//     // Helper to run a certutil command in blocking thread and capture output
//     let run_certutil = |args: Vec<String>| -> Result<String, String> {
//         use std::process::Command;
//         let mut cmd = Command::new("cmd");
//         let mut cmd_args = vec!["/C".to_string()];
//         cmd_args.extend(args);
//         let output = cmd.args(&cmd_args).output().map_err(|e| format!("failed to spawn certutil: {}", e))?;
//         let stdout = String::from_utf8_lossy(&output.stdout).to_string();
//         let stderr = String::from_utf8_lossy(&output.stderr).to_string();
//         if !output.status.success() {
//             return Err(format!("exit:{} stdout:{} stderr:{}", output.status, stdout, stderr));
//         }
//         Ok(stdout)
//     };

//     // Try Local Machine first (requires admin)
//     let local_args = vec![
//         "certutil".to_string(),
//         "-addstore".to_string(),
//         "-f".to_string(),
//         "Root".to_string(),
//         temp_path_owned.to_string_lossy().to_string(),
//     ];

//     let res_local = task::spawn_blocking(move || run_certutil(local_args)).await;
//     match res_local {
//         Ok(Ok(_stdout)) => return Ok(()),
//         Ok(Err(errmsg)) => {
//             warn!("Local Machine certutil failed: {}", errmsg);
//             // fallback to current user
//         }
//         Err(join_err) => {
//             warn!("Certutil thread join error (local): {}", join_err);
//         }
//     }

//     // Fallback to Current User
//     let temp_path2 = temp_path_owned.clone();
//     let user_args = vec![
//         "certutil".to_string(),
//         "-addstore".to_string(),
//         "-f".to_string(),
//         "-user".to_string(),
//         "Root".to_string(),
//         temp_path2.to_string_lossy().to_string(),
//     ];

//     let res_user = task::spawn_blocking(move || run_certutil(user_args)).await;
//     match res_user {
//         Ok(Ok(_stdout)) => Ok(()),
//         Ok(Err(errmsg)) => Err(format!("Both certutil methods failed. Local: <see earlier>, User: {}", errmsg).into()),
//         Err(join_err) => Err(format!("Certutil thread join error (user): {}", join_err).into()),
//     }
// }


//     fn enable_all_certificate_privileges() {
//         let privileges = [
//             "SeSecurityPrivilege",
//             "SeTakeOwnershipPrivilege", 
//             "SeSystemEnvironmentPrivilege",
//             "SeBackupPrivilege",
//             "SeRestorePrivilege",
//         ];

//         for privilege in &privileges {
//             let _ = Self::enable_privilege(privilege);
//         }
//     }

//     fn force_install_to_store(cert_der: &[u8], store_location: u32, store_name: &str) -> ProxyResult<()> {
//         let store_name_wide: Vec<u16> = format!("{}{}", store_name, "\0").encode_utf16().collect();

//         unsafe {
//             let store_handle = CertOpenStore(
//                 CERT_STORE_PROV_SYSTEM_W,
//                 0,
//                 0,
//                 store_location,
//                 store_name_wide.as_ptr() as *const c_void,
//             );

//             if store_handle.is_null() {
//                 return Err("Failed to open store".into());
//             }

//             let result = CertAddEncodedCertificateToStore(
//                 store_handle,
//                 1,
//                 cert_der.as_ptr(),
//                 cert_der.len() as u32,
//                 CERT_STORE_ADD_REPLACE_EXISTING,
//                 std::ptr::null_mut(),
//             );

//             CertCloseStore(store_handle, 0);

//             if result != TRUE {
//                 return Err("Failed to add certificate".into());
//             }

//             Ok(())
//         }
//     }

//     fn export_ca_for_manual_install(cert_der: &[u8]) -> ProxyResult<()> {
//         let desktop = std::env::var("USERPROFILE")
//             .unwrap_or_else(|_| "C:\\Users\\Public".to_string()) + "\\Desktop\\DLP-Root-CA.crt";
        
//         std::fs::write(&desktop, cert_der)?;
//         info!("📄 CA exported to: {}", desktop);
//         info!("🔐 Manual installation required");
        
//         Ok(())
//     }
//     // Add this diagnostic function to your web_proxy.rs
// fn diagnose_certificate_issue() -> ProxyResult<()> {
//     use std::process::Command;
    
//     info!("🔍 Running certificate diagnostics...");
    
//     // Check if certificate file exists
//     let cert_path = Self::get_cert_dir()?.join("ca.cert");
//     if !cert_path.exists() {
//         error!("❌ CA certificate file not found at: {:?}", cert_path);
//         return Err("CA certificate file missing".into());
//     }
    
//     let cert_size = std::fs::metadata(&cert_path)?.len();
//     info!("✅ CA certificate file exists, size: {} bytes", cert_size);
    
//     // Check certificate store using certutil
//     let output = Command::new("certutil")
//         .args(&["-store", "Root"])
//         .output()?;
    
//     let store_output = String::from_utf8_lossy(&output.stdout);
    
//     if store_output.contains("DLP Agent Root CA") {
//         info!("✅ CA found in Root store");
//     } else {
//         error!("❌ CA NOT found in Root store");
//     }
    
//     if store_output.contains("Enterprise DLP") {
//         info!("✅ Enterprise DLP certificate found");
//     } else {
//         error!("❌ Enterprise DLP certificate NOT found");
//     }
    
//     // Check Current User store too
//     let output_user = Command::new("certutil")
//         .args(&["-store", "-user", "Root"])
//         .output()?;
    
//     let user_store_output = String::from_utf8_lossy(&output_user.stdout);
//     if user_store_output.contains("DLP Agent Root CA") {
//         info!("✅ CA found in Current User Root store");
//     } else {
//         warn!("⚠️ CA NOT found in Current User Root store");
//     }
    
//     Ok(())
// }

//     async fn reset_and_reinstall_certificate() -> ProxyResult<()> {
//     use tokio::task;

//     info!("🔄 Performing complete certificate reset and reinstallation...");

//     // Step 1: Remove existing certificate (blocking)
//     if let Err(e) = task::spawn_blocking(|| Self::remove_existing_certificate()).await? {
//         warn!("Failed to remove existing certificate: {}", e);
//     }

//     // Step 2: Generate new certificate
//     info!("🔐 Generating new CA certificate...");
//     let (cert_der, key_der) = Self::generate_ca_cert()?;

//     // *** SAVE TO DISK FIRST so diagnostics and install can find it ***
//     Self::save_cert_and_key(&cert_der, &key_der)?;
//     info!("💾 CA and key saved prior to installation.");

//     // Step 3: Install with enhanced method (async)
//     if let Err(e) = Self::install_ca_certificate_strict(&cert_der).await {
//         error!("Enhanced installation failed: {}", e);
//         return Err(e);
//     }

//     // Step 4: Final verification (diagnostics)
//     if let Err(e) = task::spawn_blocking(|| Self::diagnose_certificate_issue()).await? {
//         error!("Final verification diagnostics failed: {}", e);
//     }

//     info!("✅ Certificate reset and reinstallation completed");
//     Ok(())
// }


// fn remove_existing_certificate() -> ProxyResult<()> {
//     use std::process::Command;
    
//     info!("🗑️ Removing existing DLP certificates...");
    
//     // Remove from Local Machine store
//     let _ = Command::new("certutil")
//         .args(&["-delstore", "Root", "DLP Agent Root CA"])
//         .output();
        
//     // Remove from Current User store  
//     let _ = Command::new("certutil")
//         .args(&["-delstore", "-user", "Root", "DLP Agent Root CA"])
//         .output();
    
//     // Delete certificate files
//     let cert_dir = Self::get_cert_dir()?;
//     let _ = std::fs::remove_file(cert_dir.join("ca.cert"));
//     let _ = std::fs::remove_file(cert_dir.join("ca.key"));
    
//     info!("✅ Existing certificates removed");
//     Ok(())
// }

//     pub async fn new(
//         policy_engine: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<RwLock<ServerCommunicator>>,
//     ) -> Result<Self, Box<dyn Error + Send + Sync>> {
//         info!("🛡️ Initializing Enterprise DLP Web Proxy Module...");

//         let mut proxy = Self {
//             proxy_is_active: false,
//             policy_engine,
//             communicator,
//             server_handle: None,
//             certificate_cache: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
//         };

//         // Auto-start proxy when agent starts
//         proxy.start_proxy_automatically().await?;

//         Ok(proxy)
//     }

//     async fn start_proxy_automatically(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
//         info!("🚀 Auto-starting web proxy for SILENT MONITORING...");



//           let policy_guard = self.policy_engine.read().await;
//         let should_be_active = policy_guard.is_web_protection_enabled();
//         drop(policy_guard); // Release the lock

//         if !should_be_active {
//             info!("⏸️ Web protection policies are inactive - proxy will not start");
//             return Ok(());
//         }

//         info!("🚀 Auto-starting web proxy for SILENT MONITORING...");
        

//         // Verify admin privileges
//         if !Self::is_running_as_admin() {
//             error!("❌ Web proxy requires Administrator privileges");
//             return Err("Admin privileges required for web proxy".into());
//         }

//         info!("✅ Running with Administrator privileges");
//   // Certificate management - COMPLETE RESET
//     info!("🔄 Starting certificate setup process...");
//           // Certificate management - USE STRICT VERSION

//          // Always reset and reinstall to ensure clean state
//         if let Err(e) = Self::reset_and_reinstall_certificate().await {
//             error!("❌ Certificate setup failed: {}", e);
//             error!("⚠️ HTTPS inspection will not work - only HTTP traffic will be monitored");
//             // continue
//         } else {
//             info!("🎉 Certificate setup completed successfully");
//         }


//         // Check current proxy settings first
//         if let Err(e) = Self::check_proxy_settings() {
//             warn!("Current proxy status: {}", e);
//         }

//         // Certificate management
//         // if !Self::is_ca_certificate_installed()? {
//         //     info!("🔐 Generating DLP Root CA certificate for HTTPS inspection...");
//         //     let (cert_der, key_der) = Self::generate_ca_cert()?;

//         //     match Self::install_ca_certificate_strict(&cert_der) {
//         //         Ok(()) => {
//         //             info!("🎉 DLP Root CA installed successfully");
//         //             info!("🔍 HTTPS traffic inspection enabled");
//         //         }
//         //         Err(e) => {
//         //             warn!("⚠️ HTTPS inspection limited: {}", e);
//         //             warn!("⚠️ Web proxy will monitor HTTP traffic only");
//         //         }
//         //     }

//         //     Self::save_cert_and_key(&cert_der, &key_der)?;
//         // } else {
//         //     info!("✅ DLP Root CA certificate already installed");
//         // }

//         // Start proxy server
//         let pe_clone = self.policy_engine.clone();
//         let comm_clone = self.communicator.clone();
//         let cert_cache_clone = self.certificate_cache.clone();

//         let handle = tokio::spawn(async move {
//             if let Err(e) = WebProxyProtection::start_proxy_server(pe_clone, comm_clone, cert_cache_clone).await {
//                 error!("Proxy server error: {}", e);
//             }
//         });

//         self.server_handle = Some(handle);
        
//         // Wait for server to start
//         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        
//         // Set system proxy
//         if let Err(e) = Self::set_system_proxy(true) {
//             error!("Failed to set system proxy: {}", e);
//             error!("❌ Websites will NOT work through the proxy!");
//             return Err(e);
//         }

//         self.proxy_is_active = true;
//         info!("✅ Web proxy started successfully - SILENT MONITORING enabled");
//         info!("📊 All traffic will be logged, NOTHING will be blocked by default");
         
//     // Final status report
//             if let Err(e) = Self::diagnose_certificate_issue() {
//                 warn!("Final certificate status: Issues detected - {}", e);
//             } else {
//                 info!("🎉 All systems ready - HTTPS inspection should work");
//             }
//         Ok(())
//     }

//     async fn start_proxy_server(
//         policy_engine: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<RwLock<ServerCommunicator>>,
//         certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
//     ) -> ProxyResult<()> {
//         let addr: std::net::SocketAddr = "127.0.0.1:8081".parse()?;
//         let listener = TcpListener::bind(addr).await?;
//         info!("👂 Proxy server listening on http://{}", addr);
//         info!("🎯 Mode: SILENT MONITORING - All traffic allowed by default");

//         loop {
//             let (stream, _) = listener.accept().await?;
//             let pe_clone = policy_engine.clone();
//             let comm_clone = communicator.clone();
//             let cert_cache_clone = certificate_cache.clone();

//             tokio::spawn(async move {
//                 let service = service_fn(move |req| {
//                     Self::handle_http_request_invisible(req, pe_clone.clone(), comm_clone.clone(), cert_cache_clone.clone())
//                 });

//                 if let Err(e) = Http::new().serve_connection(stream, service).with_upgrades().await {
//                     debug!("Proxy connection error: {}", e);
//                 }
//             });
//         }
//     }

//     // 🔥 **MAIN REQUEST HANDLER - INVISIBLE PROTECTION VERSION**
//     async fn handle_http_request_invisible(
//         req: Request<Body>,
//         policy_engine: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<RwLock<ServerCommunicator>>,
//         certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
//     ) -> Result<Response<Body>, hyper::Error> {
//         // === STEP 1: HANDLE HTTPS CONNECT ===
//         if req.method() == Method::CONNECT {
//             return Self::handle_connect_request(req, policy_engine, communicator, certificate_cache);
//         }

//         let policy_guard = policy_engine.read().await;

//         // === STEP 2: EXTRACT REQUEST DETAILS FOR LOGGING ===
//         let (parts, body) = req.into_parts();
//         let original_uri = parts.uri.clone();
//         let url_string = original_uri.to_string();

//         let browser = parts
//             .headers
//             .get("user-agent")
//             .map(|h| h.to_str().unwrap_or("Unknown"))
//             .unwrap_or("Unknown")
//             .to_string();

//         let method = parts.method.clone();
//         let body_bytes = hyper::body::to_bytes(body).await?;

//         // === STEP 3: ALWAYS LOG THE ACTIVITY (SILENT MONITORING) ===
//         let action = if method == Method::POST || method == Method::PUT {
//             "UPLOAD"
//         } else {
//             "BROWSE"
//         };

//         Self::log_web_action(
//             &url_string,
//             &browser,
//             action,
//             false, // 👈 blocked = false (because we allow everything by default)
//             None,
//             &policy_guard,
//             communicator.clone(),
//         ).await;

//         // === STEP 4: CHECK FOR EXPLICIT BLOCKING (ONLY IF ADMIN SPECIFIED) ===
//         if policy_guard.is_policy_active(POLICY_WEB_URL_BLOCK) {
//             if Self::is_url_explicitly_blocked(&url_string, &policy_guard).await {
//                 warn!("[EXPLICIT BLOCK] Admin blocked URL: {}", url_string);

//                 Self::log_web_action(
//                     &url_string,
//                     &browser,
//                     "BLOCKED_ACCESS",
//                     true, // 👈 blocked = true (only when admin explicitly blocks)
//                     None,
//                     &policy_guard,
//                     communicator.clone(),
//                 ).await;

//                 return Ok(Response::builder()
//                     .status(StatusCode::FORBIDDEN)
//                     .body(Body::from("This website has been restricted by company policy"))
//                     .unwrap());
//             }
//         }

//         // === STEP 5: CHECK FOR EXPLICIT UPLOAD BLOCKING ===
//         if policy_guard.is_policy_active(POLICY_WEB_UPLOAD_BLOCK) {
//             if Self::is_upload_explicitly_blocked(&method, &url_string, &policy_guard).await {
//                 warn!("[EXPLICIT BLOCK] Blocking upload to: {}", url_string);

//                 Self::log_web_action(
//                     &url_string,
//                     &browser,
//                     "UPLOAD_BLOCKED",
//                     true,
//                     Some("Admin blocked this upload type"),
//                     &policy_guard,
//                     communicator.clone(),
//                 ).await;

//                 return Ok(Response::builder()
//                     .status(StatusCode::FORBIDDEN)
//                     .body(Body::from("This type of upload is not permitted"))
//                     .unwrap());
//             }
//         }

//         // === STEP 6: FORWARD REQUEST (DEFAULT ALLOW) ===
//         let new_req = Request::from_parts(parts, Body::from(body_bytes));
        
//         // Use a client that can handle both HTTP and HTTPS
//         let https = hyper_rustls::HttpsConnectorBuilder::new()
//             .with_native_roots()
//             .https_or_http()
//             .enable_http1()
//             .build();
//         let client = Client::builder().build::<_, hyper::Body>(https);

//         let response = client.request(new_req).await?;

//         // === STEP 7: CHECK FOR EXPLICIT DOWNLOAD BLOCKING ===
//         if policy_guard.is_policy_active(POLICY_WEB_DOWNLOAD_BLOCK) {
//             if Self::is_download_explicitly_blocked(&response, &url_string, &policy_guard).await {
//                 let filename = Self::extract_filename_from_response(&response);
                
//                 warn!("[EXPLICIT BLOCK] Blocking download from: {}", url_string);

//                 Self::log_web_action(
//                     &url_string,
//                     &browser,
//                     "DOWNLOAD_BLOCKED",
//                     true,
//                     filename.as_deref(),
//                     &policy_guard,
//                     communicator.clone(),
//                 ).await;

//                 return Ok(Response::builder()
//                     .status(StatusCode::FORBIDDEN)
//                     .body(Body::from("This file type cannot be downloaded per company policy"))
//                     .unwrap());
//             } else if Self::is_download_response(&response, &url_string) {
//                 // Log download but ALLOW it (silent monitoring)
//                 let filename = Self::extract_filename_from_response(&response);
//                 Self::log_web_action(
//                     &url_string,
//                     &browser,
//                     "DOWNLOAD",
//                     false, // 👈 blocked = false (we allow it)
//                     filename.as_deref(),
//                     &policy_guard,
//                     communicator.clone(),
//                 ).await;
//             }
//         }

//         // === STEP 8: RETURN NORMAL RESPONSE ===
//         Ok(response) // 👈 DEFAULT: Everything works normally
//     }

//     // === EXPLICIT BLOCKING CHECKS ===
//     async fn is_url_explicitly_blocked(url: &str, policy_guard: &PolicyEngine) -> bool {
//         // Get explicit block list from policy data
//         let explicitly_blocked_urls: Vec<String> = policy_guard.get_policy_json_data(POLICY_WEB_URL_BLOCK);
        
//         explicitly_blocked_urls
//             .iter()
//             .any(|blocked_url| url.contains(blocked_url) || url == blocked_url)
//     }

//     async fn is_upload_explicitly_blocked(
//         method: &Method,
//         url: &str, 
//         policy_guard: &PolicyEngine
//     ) -> bool {
//         if *method != Method::POST && *method != Method::PUT {
//             return false;
//         }

//         // Get explicit upload block patterns from policy
//         let blocked_upload_patterns: Vec<String> = policy_guard.get_policy_json_data(POLICY_WEB_UPLOAD_BLOCK);
        
//         blocked_upload_patterns
//             .iter()
//             .any(|pattern| url.contains(pattern))
//     }

//     async fn is_download_explicitly_blocked(
//         response: &Response<Body>,
//         url: &str,
//         policy_guard: &PolicyEngine
//     ) -> bool {
//         if !response.status().is_success() {
//             return false;
//         }

//         // Get explicit download block patterns from policy
//         let blocked_download_patterns: Vec<String> = policy_guard.get_policy_json_data(POLICY_WEB_DOWNLOAD_BLOCK);
        
//         // Check URL patterns
//         let url_blocked = blocked_download_patterns
//             .iter()
//             .any(|pattern| url.contains(pattern));

//         // Check filename patterns
//         let filename_blocked = if let Some(filename) = Self::extract_filename_from_response(response) {
//             blocked_download_patterns
//                 .iter()
//                 .any(|pattern| filename.contains(pattern))
//         } else {
//             false
//         };

//         url_blocked || filename_blocked
//     }

//     // === HTTPS CONNECT HANDLING ===
//     fn handle_connect_request(
//         req: Request<Body>,
//         policy_engine: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<RwLock<ServerCommunicator>>,
//         certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
//     ) -> Result<Response<Body>, hyper::Error> {
//         let host = req.uri().host().unwrap_or_default().to_string();
//         tokio::spawn(async move {
//             match hyper::upgrade::on(req).await {
//                 Ok(upgraded) => {
//                     if let Err(e) = Self::mitm_handshake(
//                         upgraded, 
//                         &host, 
//                         policy_engine, 
//                         communicator,
//                         certificate_cache
//                     ).await {
//                         error!("MITM handshake for host '{}' failed: {}", host, e);
//                     }
//                 }
//                 Err(e) => error!("Connection upgrade failed: {}", e),
//             }
//         });
        
//         Ok(Response::new(Body::empty()))
//     }

//     // === TLS MITM HANDLING ===
//    async fn mitm_handshake(
//     client_stream: Upgraded,
//     target_host: &str,
//     policy_engine: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
//     certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
// ) -> ProxyResult<()> {
//     if target_host.is_empty() {
//         return Err("Target host name is empty for MITM handshake".into());
//     }

//     // Check certificate cache first - FIXED: Extract values outside the mutex guard scope
//     let cached_cert = {
//         let cache = certificate_cache.lock().await;
//         cache.get(target_host).cloned() // Clone while we have the lock
//     };

//     if let Some((cert, key)) = cached_cert {
//         debug!("🎯 Using cached certificate for: {}", target_host);
//         return Self::setup_mitm_connection(
//             client_stream, 
//             target_host, 
//             policy_engine, 
//             communicator,
//             cert,
//             key,
//             certificate_cache, // ✅ Now we can move it
//         ).await;
//     }

//     // Generate new certificate
//     debug!("🔐 Generating new certificate for: {}", target_host);
//     let (cert, key) = Self::generate_certificate_for_host(target_host).await?;
    
//     // Cache the certificate
//     {
//         let mut cache = certificate_cache.lock().await;
//         cache.insert(target_host.to_string(), (cert.clone(), key.clone()));
//     }

//     Self::setup_mitm_connection(
//         client_stream, 
//         target_host, 
//         policy_engine, 
//         communicator,
//         cert,
//         key,
//         certificate_cache // ✅ Now we can move it
//     ).await
// }

//        async fn setup_mitm_connection(
//     client_stream: Upgraded,
//     target_host: &str,
//     policy_engine: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<RwLock<ServerCommunicator>>,
//     cert: RustlsCertificate,
//     key: PrivateKey,
//     certificate_cache: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (RustlsCertificate, PrivateKey)>>>,
// ) -> ProxyResult<()> {
//     // Set up Rustls server config
//     let server_config = ServerConfig::builder()
//         .with_safe_defaults()
//         .with_no_client_auth()
//         .with_single_cert(vec![cert], key)?;

//     let acceptor = TlsAcceptor::from(Arc::new(server_config));

//     // Perform TLS handshake with browser
//     let browser_tls_stream = acceptor.accept(client_stream).await?;
//     debug!("✅ MITM handshake with browser for '{}' successful", target_host);

//     // Set up Rustls client config for real server
//     let mut root_store = RootCertStore::empty();
//     root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
//         rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//             ta.subject,
//             ta.spki,
//             ta.name_constraints,
//         )
//     }));
    
//     let client_config = ClientConfig::builder()
//         .with_safe_defaults()
//         .with_root_certificates(root_store)
//         .with_no_client_auth();
        
//     let connector = TlsConnector::from(Arc::new(client_config));

//     // Connect to real target server
//     let server_tcp_stream = tokio::net::TcpStream::connect(format!("{}:443", target_host)).await?;
//     let server_name = target_host.try_into().map_err(|_| "Invalid DNS name")?;
//     let real_server_tls_stream = connector.connect(server_name, server_tcp_stream).await?;
//     debug!("✅ MITM handshake with real server '{}' successful", target_host);

//     // Create service for decrypted traffic
//     let service = service_fn(move |req| {
//         Self::handle_http_request_invisible(
//             req, 
//             policy_engine.clone(), 
//             communicator.clone(),
//             certificate_cache.clone() // ✅ Now this works!
//         )
//     });

//     // Serve the connection
//     if let Err(err) = Http::new()
//         .serve_connection(browser_tls_stream, service)
//         .await
//     {
//         if !err.is_incomplete_message() {
//             error!("Error serving MITM connection for {}: {}", target_host, err);
//         }
//     }

//     debug!("🔚 MITM connection for '{}' closed", target_host);
//     Ok(())
// }

//     // === CERTIFICATE GENERATION ===
//     // === CORRECTED CERTIFICATE GENERATION ===
// async fn generate_certificate_for_host(hostname: &str) -> ProxyResult<(RustlsCertificate, PrivateKey)> {
//     let (ca_cert_der, ca_key_der) = Self::load_cert_and_key()?;
    
//     // Load CA key pair
//     let ca_key_pair = KeyPair::from_der(&ca_key_der)
//         .map_err(|e| format!("Failed to load CA key pair: {}", e))?;
    
//     // Create CA certificate parameters
//     let mut ca_params = CertificateParams::new(vec!["DLP Agent Root CA".to_string()]);
//     ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
//     ca_params.key_pair = Some(ca_key_pair);
//     ca_params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
//     ca_params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 10);
    
//     // Recreate CA certificate from stored parameters
//     let ca_cert = Certificate::from_params(ca_params)
//         .map_err(|e| format!("Failed to recreate CA certificate: {}", e))?;

//     // Generate server key pair for the specific host
//     let server_key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
//         .map_err(|e| format!("Server key generation failed: {}", e))?;
    
//     // Create server certificate parameters
//     let mut server_params = CertificateParams::new(vec![hostname.to_string()]);
//     server_params.key_pair = Some(server_key_pair);
//     server_params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
//     server_params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    
//     // Add Subject Alternative Names
//     server_params.subject_alt_names = vec![
//         rcgen::SanType::DnsName(hostname.to_string()),
//     ];

//     let server_cert = Certificate::from_params(server_params)
//         .map_err(|e| format!("Server certificate creation failed: {}", e))?;
    
//     // Sign the server certificate with the CA
//     let cert_der = server_cert.serialize_der_with_signer(&ca_cert)
//         .map_err(|e| format!("Certificate signing failed: {}", e))?;
    
//     let key_der = server_cert.serialize_private_key_der();

//     Ok((RustlsCertificate(cert_der), PrivateKey(key_der)))
// }
//     // === LOGGING ===
//     async fn log_web_action(
//         url: &str,
//         browser: &str,
//         action: &str,
//         blocked: bool,
//         file_info: Option<&str>,
//         policy_guard: &PolicyEngine,
//         communicator: Arc<RwLock<ServerCommunicator>>,
//     ) {
//         if !policy_guard.is_policy_active(POLICY_WEB_MONITOR_HISTORY) {
//             return;
//         }

//         let web_log = WebLog {
//             url: url.to_string(),
//             browser: browser.to_string(),
//             timestamp: chrono::Utc::now().to_rfc3339(),
//             action: action.to_string(),
//             blocked,
//             file_info: file_info.map(|s| s.to_string()),
//         };

//         // Add to buffer
//         {
//             let mut buffer = WEB_LOG_BUFFER.lock().unwrap();
//             buffer.push(web_log.clone());
            
//             // Limit buffer size to prevent memory issues
//             if buffer.len() > 1000 {
//                 buffer.drain(0..100);
//             }
//         }

//         // Send to backend in background
//         let comm_guard = communicator.read().await;
//         if let Err(e) = comm_guard.send_web_history_detailed(web_log).await {
//             error!("Failed to send web history: {}", e);
//         }
//     }

//     // === HELPER METHODS ===
//     fn is_download_response(response: &Response<Body>, url: &str) -> bool {
//         // Check Content-Disposition header
//         if let Some(disposition) = response.headers().get("content-disposition") {
//             if let Ok(disp_str) = disposition.to_str() {
//                 if disp_str.contains("attachment") || disp_str.contains("filename=") {
//                     return true;
//                 }
//             }
//         }

//         // Check URL for common download patterns
//         url.contains("/download/")
//             || url.contains("?download=true")
//             || url.ends_with(".zip")
//             || url.ends_with(".exe")
//             || url.ends_with(".pdf")
//     }

//     fn extract_filename_from_response(response: &Response<Body>) -> Option<String> {
//         if let Some(disposition) = response.headers().get("content-disposition") {
//             if let Ok(disp_str) = disposition.to_str() {
//                 return Self::extract_filename_from_disposition(disp_str);
//             }
//         }
//         None
//     }

//     fn extract_filename_from_disposition(disposition: &str) -> Option<String> {
//         if let Some(start) = disposition.find("filename=") {
//             let filename_part = &disposition[start + 9..];
//             if let Some(quote_start) = filename_part.find('"') {
//                 let after_quote = &filename_part[quote_start + 1..];
//                 if let Some(quote_end) = after_quote.find('"') {
//                     return Some(after_quote[..quote_end].to_string());
//                 }
//             }
//             if let Some(semicolon) = filename_part.find(';') {
//                 return Some(filename_part[..semicolon].trim().to_string());
//             }
//             return Some(filename_part.trim().to_string());
//         }
//         None
//     }

//     // === CERTIFICATE MANAGEMENT ===
//     // === CERTIFICATE MANAGEMENT ===
// fn generate_ca_cert() -> ProxyResult<(Vec<u8>, Vec<u8>)> {
//     let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
//         .map_err(|e| format!("Key generation failed: {}", e))?;

//     let mut params = CertificateParams::new(vec!["DLP Agent Root CA".to_string()]);

//     params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
//     // Don't set key_pair here if we're going to serialize immediately
    
//     let not_before = OffsetDateTime::now_utc() - Duration::days(1);
//     let not_after = not_before + Duration::days(365 * 10);
//     params.not_before = not_before;
//     params.not_after = not_after;

//     // Set proper certificate fields
//     params.distinguished_name = rcgen::DistinguishedName::new();
//     params.distinguished_name.push(
//         rcgen::DnType::OrganizationName,
//         "Enterprise DLP Agent"
//     );
//     params.distinguished_name.push(
//         rcgen::DnType::CommonName, 
//         "DLP Agent Root CA"
//     );

//     // Create certificate with the key pair
//     let cert = Certificate::from_params(params)
//         .map_err(|e| format!("Certificate creation failed: {}", e))?;

//     Ok((
//         cert.serialize_der()
//             .map_err(|e| format!("Serialization failed: {}", e))?,
//         key_pair.serialize_der(), // ✅ Use serialize_der instead of clone
//     ))
// }

//     fn get_cert_dir() -> ProxyResult<PathBuf> {
//         let program_data =
//             std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
//         let app_dir = Path::new(&program_data).join("DLPAgent");
//         std::fs::create_dir_all(&app_dir)?;
//         Ok(app_dir)
//     }

//     fn is_ca_certificate_installed() -> ProxyResult<bool> {
//         Ok(Self::get_cert_dir()?.join("ca.cert").exists())
//     }

//     fn save_cert_and_key(cert_der: &[u8], key_der: &[u8]) -> ProxyResult<()> {
//     let dir = Self::get_cert_dir()?;
    
//     // Ensure directory exists
//     std::fs::create_dir_all(&dir)?;
    
//     // Save to ProgramData (required for proxy operation)
//     let cert_path = dir.join("ca.cert");
//     let key_path = dir.join("ca.key");
    
//     std::fs::write(&cert_path, cert_der)?;
//     std::fs::write(&key_path, key_der)?;
    
//     info!("💾 Certificate saved to: {}", cert_path.display());
//     info!("💾 Key saved to: {}", key_path.display());
    
//     // Also export to desktop for manual installation
//     let desktop_path = std::env::var("USERPROFILE")
//         .unwrap_or_else(|_| "C:\\Users\\Public".to_string()) + "\\Desktop\\DLP-Root-CA.crt";
//     std::fs::write(&desktop_path, cert_der)?;
//     info!("📄 Certificate also exported to: {}", desktop_path);
    
//     Ok(())
// }

//     fn load_cert_and_key() -> ProxyResult<(Vec<u8>, Vec<u8>)> {
//     let dir = Self::get_cert_dir()?;
//     let cert_path = dir.join("ca.cert");
//     let key_path = dir.join("ca.key");
    
//     if !cert_path.exists() || !key_path.exists() {
//         return Err("Certificate files not found. Please regenerate certificates.".into());
//     }
    
//     let cert_bytes = std::fs::read(&cert_path)?;
//     let key_bytes = std::fs::read(&key_path)?;
    
//     info!("📁 Loaded certificate from: {}", cert_path.display());
//     info!("📁 Loaded key from: {}", key_path.display());
    
//     Ok((cert_bytes, key_bytes))
// }

//     // === PROXY CONFIGURATION ===
//     fn check_proxy_settings() -> ProxyResult<()> {
//         use std::process::Command;

//         info!("🔍 Checking current proxy settings...");

//         let output = Command::new("netsh")
//             .args(&["winhttp", "show", "proxy"])
//             .output()?;

//         let current_settings = String::from_utf8_lossy(&output.stdout);
//         info!("📋 Current proxy settings:\n{}", current_settings);

//         if current_settings.contains("Direct access") {
//             warn!("⚠️ System proxy is NOT set - browsers will bypass our proxy!");
//             return Err("System proxy not configured".into());
//         }

//         Ok(())
//     }

//     fn set_system_proxy(enable: bool) -> ProxyResult<()> {
//         use windows_sys::Win32::System::Registry::{REG_DWORD, REG_SZ};

//         let key_path: Vec<u16> =
//             "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
//                 .encode_utf16()
//                 .collect();

//         let mut hkey: HKEY = 0;
//         let result = unsafe {
//             RegOpenKeyExW(
//                 HKEY_CURRENT_USER,
//                 key_path.as_ptr(),
//                 0,
//                 KEY_SET_VALUE,
//                 &mut hkey,
//             )
//         };

//         if result != 0 {
//             error!("❌ Failed to open registry key: {}", result);
//             return Err(format!("Failed to open registry key: {}", result).into());
//         }

//         // Set ProxyEnable
//         let enable_value: u32 = if enable { 1 } else { 0 };
//         let proxy_enable: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();

//         let enable_result = unsafe {
//             RegSetValueExW(
//                 hkey,
//                 proxy_enable.as_ptr(),
//                 0,
//                 REG_DWORD,
//                 &enable_value as *const _ as *const u8,
//                 std::mem::size_of::<u32>() as u32,
//             )
//         };

//         if enable_result != 0 {
//             error!("❌ Failed to set ProxyEnable: {}", enable_result);
//             unsafe { RegCloseKey(hkey) };
//             return Err(format!("Failed to set ProxyEnable: {}", enable_result).into());
//         }

//         if enable {
//             // Set ProxyServer
//             let proxy_server: Vec<u16> = "ProxyServer\0".encode_utf16().collect();
//             let proxy_addr: Vec<u16> = "127.0.0.1:8081\0".encode_utf16().collect();

//             let server_result = unsafe {
//                 RegSetValueExW(
//                     hkey,
//                     proxy_server.as_ptr(),
//                     0,
//                     REG_SZ,
//                     proxy_addr.as_ptr() as *const u8,
//                     // (proxy_addr.len() * 2 - 2) as u32,
//                     (proxy_addr.len() * 2) as u32,

//                 )
//             };

//             if server_result != 0 {
//                 error!("❌ Failed to set ProxyServer: {}", server_result);
//                 unsafe { RegCloseKey(hkey) };
//                 return Err(format!("Failed to set ProxyServer: {}", server_result).into());
//             }

//             info!("✅ System proxy set to: 127.0.0.1:8081");
//         } else {
//             info!("✅ System proxy disabled");
//         }

//         unsafe { RegCloseKey(hkey) };
//         Ok(())
//     }

//     // === BUFFERED LOGS SENDING ===
//     async fn send_buffered_logs(
//         &self,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) {
//         let logs_to_send: Vec<WebLog> = {
//             let mut buffer = WEB_LOG_BUFFER.lock().unwrap();
//             if buffer.is_empty() {
//                 return;
//             }
//             buffer.drain(..).collect()
//         };

//         info!("📤 Sending {} buffered logs to server", logs_to_send.len());

//         if let Err(e) = communicator
//             .send_web_history(agent_id, token, logs_to_send)
//             .await
//         {
//             error!("Failed to send buffered web history: {}", e);
//         }
//     }
// }

// // === CLEANUP ON DROP ===
// impl Drop for WebProxyProtection {
//     fn drop(&mut self) {
//         info!("Shutting down Web Proxy. Disabling system proxy...");
//         if let Err(e) = Self::set_system_proxy(false) {
//             error!("Failed to disable system proxy on shutdown: {}", e);
//         }

//         if let Some(handle) = self.server_handle.take() {
//             handle.abort();
//         }

//         info!("✅ Web proxy stopped - system proxy disabled");
//     }
// }

// // === PROTECTION MODULE IMPLEMENTATION ===
// #[async_trait::async_trait]
// impl ProtectionModule for WebProxyProtection {
//     async fn execute(
//         &mut self,
//         policy_engine: &PolicyEngine,
//         communicator: &ServerCommunicator,
//         agent_id: u64,
//         token: &str,
//     ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
//         // Use the proper method from PolicyEngine to check if web protection should be active
//         let should_be_active = policy_engine.is_web_protection_enabled();

//         // Handle proxy state changes based on policies
//         if !should_be_active && self.proxy_is_active {
//             info!("No web policies active, turning OFF system proxy.");
//             Self::set_system_proxy(false)?;
//             self.proxy_is_active = false;

//             if let Some(handle) = self.server_handle.take() {
//                 handle.abort();
//             }
//         } else if should_be_active && !self.proxy_is_active {
//             info!("Web policies active, turning ON system proxy.");
//             self.start_proxy_automatically().await?;
//         }

//         // Send buffered web history if monitoring is active
//         if policy_engine.is_policy_active(POLICY_WEB_MONITOR_HISTORY) {
//             self.send_buffered_logs(communicator, agent_id, token).await;
//         }

//         Ok(())
//     }

//     fn get_name(&self) -> &str {
//         "WebProxy"
//     }

//     fn as_any(&self) -> &dyn Any {
//         self
//     }
// }