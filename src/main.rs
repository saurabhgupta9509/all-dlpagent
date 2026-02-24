use std::error::Error;
use std::io::{self};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use once_cell::sync::Lazy;
// DLP Agent modules
pub mod agent_core;
pub mod capabilities;
pub mod communication;
pub mod config;
pub mod gui;
pub mod policy_engine;
pub mod protection_modules;
pub mod policy_constants;
// Re-export main types
pub use agent_core::AgentCore;
pub use communication::ServerCommunicator;
pub use gui::AgentGUI;
pub use policy_engine::{Policy, PolicyEngine};

// Windows API imports for admin elevation
use std::ffi::c_void;
use std::os::windows::prelude::OsStrExt;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess,
    OpenProcessToken,
    WaitForSingleObject,
    INFINITE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

// Global configuration for timing
static TIMING_CONFIG: Lazy<GlobalTimingConfig> = Lazy::new(|| GlobalTimingConfig {
    agent_poll_interval: Duration::from_secs(15),  // Changed from 2 to 30 seconds
    ocr_interval: Duration::from_secs(5),
    security_monitor_maintenance: Duration::from_secs(60),
    policy_check_interval: Duration::from_secs(30),  // Check policies every 30s
    token_refresh_interval: Duration::from_secs(300), // Refresh token every 5 minutes
});

#[derive(Debug)]
pub struct GlobalTimingConfig {
    agent_poll_interval: Duration,
    ocr_interval: Duration,
    security_monitor_maintenance: Duration,
    policy_check_interval: Duration,
    token_refresh_interval: Duration,
}

// Admin elevation functions
pub fn is_running_as_admin() -> bool {
    unsafe {
        let mut token_handle: HANDLE = 0;
        let current_process = GetCurrentProcess();
        if OpenProcessToken(current_process, 0x0008, &mut token_handle) != TRUE {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut return_length = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length
        );

        CloseHandle(token_handle);
        result == TRUE && elevation.TokenIsElevated != 0
    }
}

fn request_elevation() {
    log::warn!("Agent is not running as admin. Requesting elevation...");

    unsafe {
        let exe_path = std::env::current_exe().unwrap();
        let exe_path_wide: Vec<u16> = exe_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let operation: Vec<u16> = "runas\0".encode_utf16().collect();

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: operation.as_ptr(),
            lpFile: exe_path_wide.as_ptr(),
            lpParameters: std::ptr::null(), // No args
            lpDirectory: std::ptr::null(),
            nShow: SW_SHOWNORMAL,
            ..std::mem::zeroed()
        };

        if ShellExecuteExW(&mut sei as *mut _) == TRUE {
            if sei.hProcess != 0 {
                WaitForSingleObject(sei.hProcess, INFINITE);
                CloseHandle(sei.hProcess);
            }
        } else {
            log::error!("Failed to elevate. User cancelled or an error occurred.");
        }
    }
}

fn wait_for_keypress() {
    println!("Press Enter to exit...");
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // === ADMIN CHECK AT STARTUP ===
    if !is_running_as_admin() {
        request_elevation();
        return Ok(());
    }

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("🚀 Starting DLP Protection Agent with Security Monitor... (Running as Administrator)");

    // === SECURITY MONITOR SETUP ===
    println!("📁 Setting up Security Monitor directories...");
    std::fs::create_dir_all("screenshots")
        .unwrap_or_else(|e| eprintln!("Warning: Could not create screenshots directory: {}", e));
    std::fs::create_dir_all("logs")
        .unwrap_or_else(|e| eprintln!("Warning: Could not create logs directory: {}", e));
    std::fs::create_dir_all("certificates")
        .unwrap_or_else(|e| eprintln!("Warning: Could not create certificates directory: {}", e));

    // Check for tessdata
    if !std::path::Path::new("tessdata/eng.traineddata").exists() {
        eprintln!("❌ ERROR: tessdata/eng.traineddata not found!");
        eprintln!("💡 Please download eng.traineddata from:");
        eprintln!("   https://github.com/tesseract-ocr/tessdata/raw/main/eng.traineddata");
        eprintln!("   and place it in a 'tessdata' folder in your application directory.");
        wait_for_keypress();
        return Ok(());
    }

    println!("✅ Security Monitor directories created successfully");

    // === DLP AGENT AUTHENTICATION ===
    let mut gui = AgentGUI::new();

    // --- FIRST CHECKPOINT: Authentication ---
    match gui.run_authentication_only().await {
        Ok(()) => {
            log::info!("✅ GUI authentication successful.");
        }
        Err(e) => {
            log::error!("❌ Authentication failed: {}", e);

            log::error!("---------------------------------");
            log::error!("--- AUTHENTICATION FAILED ---");
            log::error!("--- PRESS ENTER TO EXIT ---");
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer).unwrap();

            return Err(e);
        }
    }

    if gui.is_authenticated {
        log::info!("✅ Authentication successful. Starting AgentCore service and Security Monitor...");

        if let Some(communicator) = gui.communicator {
            let communicator_arc = Arc::new(RwLock::new(communicator));
            let agent_id = gui.agent_id;
            let token = gui.token.clone();
            let username = gui.username.clone();

            // === START BOTH SERVICES IN PARALLEL ===
            let agent_future = start_agent_core(
                communicator_arc.clone(),
                agent_id,
                token.clone(),
                username
            );

          
            // Run both services concurrently
            tokio::select! {
                agent_result = agent_future => {
                    if let Err(e) = agent_result {
                        log::error!("❌ AgentCore service failed: {}", e);
                        return Err(e);
                    }
                }
            
            }
        } else {
            let error_msg = "❌ No communicator available after authentication.".to_string();
            log::error!("{}", error_msg);
            return Err(error_msg.into());
        }
    } else {
        let error_msg = "⚠️ Authentication failed or cancelled. Exiting.".to_string();
        log::warn!("{}", error_msg);
        return Err(error_msg.into());
    }

    println!("👋 All services stopped");
    wait_for_keypress();
    Ok(())
}

// Helper function to start AgentCore
async fn start_agent_core(
    communicator: Arc<RwLock<ServerCommunicator>>,
    agent_id: u64,
    token: String,
    username: String
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut agent_core = AgentCore::new();

    agent_core.communicator = communicator;
    agent_core.agent_id = agent_id;
    agent_core.token = format!("Bearer {}", token);

    // Initialize AgentCore
    if let Err(e) = agent_core.initialize(username).await {
        log::error!("❌ AgentCore initialization failed: {}", e);

        log::error!("---------------------------------");
        log::error!("--- AGENT FAILED TO START ---");
        log::error!("--- PRESS ENTER TO EXIT ---");
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).unwrap();

        return Err(e);
    }

    log::info!("✅ AgentCore initialized. Starting main protection loop...");

    // Run AgentCore
    if let Err(e) = agent_core.run().await {
        log::error!("❌ AgentCore run failed: {}", e);
        return Err(e);
    }

    Ok(())
}

