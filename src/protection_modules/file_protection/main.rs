// // Og

// pub mod fltlib;
// use fltlib::*;
// use windows_sys::Win32::Foundation::*;
// use std::ptr;
// fn wide(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(Some(0)).collect()
// }
// use std::collections::HashMap;
// type PolicyKey = (String, bool); // (path, is_folder)
// static mut ACTIVE_POLICIES: Option<HashMap<PolicyKey, FilePolicy>> = None;
// #[repr(C)]
// #[derive(Clone, Copy)]
// struct FilePolicy {
//     pub path: [u16; 260],
//     pub is_folder: u8,
//     pub block_read: u8,
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_all: u8,
//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

// fn make_policy(
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> FilePolicy {
//     let mut p = FilePolicy {
//         path: [0; 260],
//         is_folder: if is_folder { 1 } else { 0 },
//         block_read,
//         block_write,
//         block_delete,
//         block_rename,
//         block_create,
//         block_all,
//         timestamp: std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .unwrap()
//             .as_secs(),
//         added_by: [0; 64],
//         reserved: [0; 8],
//     };

//     let wide_str: Vec<u16> = path.encode_utf16().collect();
//     let copy_len = wide_str.len().min(259);
//     p.path[..copy_len].copy_from_slice(&wide_str[..copy_len]);

//     // Ensure folder paths end with backslash
//     if is_folder && copy_len > 0 && p.path[copy_len-1] != b'\\' as u16 {
//         p.path[copy_len] = b'\\' as u16;
//     }

//     p
// }

// fn remove_policy(path: &str, is_folder: bool) -> FilePolicy {
//     make_policy(path, is_folder, 0, 0, 0, 0, 0, 0)
// }

// fn send_policy(handle: HANDLE, policy: &FilePolicy, description: &str) -> bool {
//     let mut returned: u32 = 0;
//     let status = unsafe {
//         FilterSendMessage(
//             handle,
//             policy as *const _ as _,
//             std::mem::size_of::<FilePolicy>() as u32,
//             ptr::null_mut(),
//             0,
//             &mut returned,
//         )
//     };

//     if status == 0 {
//         println!("✅ {} sent successfully", description);
//         true
//     } else {
//         println!("❌ Failed to send {}: NTSTATUS=0x{:X}", description, status);
//         false
//     }
// }

// fn main() {
//     println!("DLP PHASE-1 - NT PATHS ONLY");
//     println!("============================\n");

//     println!("Connecting to kernel driver...");

//     let mut handle: HANDLE = 0;
//     let port = wide("\\DlpPort");

//     let status = unsafe {
//         FilterConnectCommunicationPort(
//             port.as_ptr(),
//             0,
//             ptr::null(),
//             0,
//             ptr::null_mut(),
//             &mut handle,
//         )
//     };

//     if status != 0 {
//         println!("❌ Failed to connect to kernel: NTSTATUS=0x{:X}", status);
//         return;
//     }

//     println!("✅ Connected to kernel driver!\n");

//     println!("IMPORTANT: Using NT paths only\n");
//     println!("Example NT paths (use DebugView to see real paths):");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\TopSecret\\\\");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\Users\\\\Test\\\\file.txt");
//     println!();

//     // TEST 1: Full immutability for folder
//     println!("1. Setting immutability for NT folder:");
//     let nt_folder = make_policy(
//         "\\Device\\HarddiskVolume4\\TopSecret", // CHANGE THIS TO REAL NT PATH
//         true,    // folder
//         1,       // block_read = 0 (ALLOW reading)
//         1,       // block_write = 1 (BLOCK modifications)
//         1,       // block_delete = 1 (BLOCK deletion)
//         1,       // block_rename = 1 (BLOCK rename)
//         1,       // block_create = 1 (BLOCK new files)
//         0       // block_all = 0
//     );
//     send_policy(handle, &nt_folder, "NT folder immutability");

//     // TEST 2: Test with specific file
//     println!("\n2. Protecting specific file:");
//     let nt_file = make_policy(
//         "\\Device\\HarddiskVolume5\\", // CHANGE THIS
//         false,   // file
//         0,       // block_read = 0
//         0,       // block_write = 1
//         0,       // block_delete = 1
//         0,       // block_rename = 1
//         0,       // block_create = 0 (N/A for files)
//         0        // block_all = 0
//     );
//     send_policy(handle, &nt_file, "NT file protection");

//     println!("\n============================");
//     println!("PHASE-1 ACTIVE");
//     println!("============================");
//     println!("Will BLOCK:");
//     println!("  • Write/modify");
//     println!("  • Delete");
//     println!("  • Rename");
//     println!("  • Create new files");
//     println!("  • Memory-mapped writes (PDF/Office)");
//     println!("\nWill ALLOW:");
//     println!("  • Read/open/view");
//     println!("  • Directory listing");
//     println!("============================\n");

//     println!("To get REAL NT paths:");
//     println!("1. Load the driver");
//     println!("2. Open DebugView as Administrator");
//     println!("3. Try to access a file");
//     println!("4. Look for 'DLP[CREATE]:' messages");
//     println!("5. Copy the exact NT path shown\n");

//     println!("Commands:");
//     println!("  test   - Send test paths");
//     println!("  remove <path> - Remove policy");
//     println!("  exit   - Quit");

//     loop {
//         print!("> ");
//         std::io::Write::flush(&mut std::io::stdout()).unwrap();

//         let mut input = String::new();
//         std::io::stdin().read_line(&mut input).unwrap();
//         let input = input.trim().to_lowercase();

//         match input.as_str() {
//             "exit" => {
//                 println!("Exiting...");
//                 break;
//             },
//             "test" => {
//                 println!("Test paths sent. Check DebugView for actual NT paths.");
//             },
//             cmd if cmd.starts_with("remove ") => {
//                 let path = &cmd[7..].trim();
//                 println!("Removing policy for: {}", path);
//                 let remove = remove_policy(path, true);
//                 send_policy(handle, &remove, &format!("Remove policy: {}", path));
//             },
//             _ => println!("Unknown command. Type 'test', 'remove <path>', or 'exit'"),
//         }
//     }

//     println!("DLP Agent terminated.");
// }

//1st

// main.rs - DLP Rust Agent with proper error handling
// pub mod fltlib;

// use fltlib::*;
// use windows_sys::Win32::Foundation::*;
// use std::ptr;
// use std::io::{self, Write};

// fn wide(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(Some(0)).collect()
// }

// #[repr(C)]
// #[derive(Clone, Copy)]
// struct FilePolicy {
//     pub path: [u16; 260],
//     pub is_folder: u8,
//     pub block_read: u8,
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_all: u8,
//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

// fn make_policy(
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> FilePolicy {
//     let mut p = FilePolicy {
//         path: [0; 260],
//         is_folder: if is_folder { 1 } else { 0 },
//         block_read,
//         block_write,
//         block_delete,
//         block_rename,
//         block_create,
//         block_all,
//         timestamp: std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .unwrap_or_default()
//             .as_secs(),
//         added_by: [0; 64],
//         reserved: [0; 8],
//     };

//     let wide_str: Vec<u16> = path.encode_utf16().collect();
//     let copy_len = wide_str.len().min(259);
//     if copy_len > 0 {
//         p.path[..copy_len].copy_from_slice(&wide_str[..copy_len]);
//     }

//     // Ensure folder paths end with backslash
//     if is_folder && copy_len > 0 && p.path[copy_len-1] != b'\\' as u16 {
//         if copy_len < 259 {
//             p.path[copy_len] = b'\\' as u16;
//         }
//     }

//     p
// }

// fn remove_policy(path: &str, is_folder: bool) -> FilePolicy {
//     make_policy(path, is_folder, 0, 0, 0, 0, 0, 0)
// }

// fn send_policy(handle: HANDLE, policy: &FilePolicy, description: &str) -> bool {
//     let mut returned: u32 = 0;
//     let status = unsafe {
//         FilterSendMessage(
//             handle,
//             policy as *const _ as _,
//             std::mem::size_of::<FilePolicy>() as u32,
//             ptr::null_mut(),
//             0,
//             &mut returned,
//         )
//     };

//     if status == 0 {
//         println!("✅ {} sent successfully", description);
//         true
//     } else {
//         println!("❌ Failed to send {}: NTSTATUS=0x{:X}", description, status);
//         false
//     }
// }

// fn wait_for_exit() {
//     println!("\nPress Enter to exit...");
//     let mut input = String::new();
//     let _ = io::stdin().read_line(&mut input);
// }

// fn main() {
//     // Set panic hook to prevent silent crashes
//     std::panic::set_hook(Box::new(|panic_info| {
//         println!("\n❌ RUST PANIC OCCURRED!");
//         println!("Error: {}", panic_info);
//         wait_for_exit();
//     }));

//     println!("DLP Rust Agent - Phase 1 (Safe Version)");
//     println!("=======================================\n");

//     // Check if running as administrator (optional)
//     println!("Note: This program needs Administrator privileges");
//     println!("If it closes immediately, run Command Prompt as Admin\n");

//     println!("Step 1: Checking driver connection...");

//     let mut handle: HANDLE = 0;
//     let port = wide("\\DlpPort");

//     println!("Attempting to connect to \\\\DlpPort...");

//     let status = unsafe {
//         FilterConnectCommunicationPort(
//             port.as_ptr(),
//             0,
//             ptr::null(),
//             0,
//             ptr::null_mut(),
//             &mut handle,
//         )
//     };

//     if status != 0 {
//         println!("❌ FAILED to connect to kernel driver!");
//         println!("NTSTATUS error code: 0x{:X}", status);
//         println!("\nPossible solutions:");
//         println!("1. Run Command Prompt AS ADMINISTRATOR");
//         println!("2. Make sure DLP driver is loaded:");
//         println!("   sc query DLP");
//         println!("   If not running: sc start DLP");
//         println!("3. Driver might not be installed:");
//         println!("   Install driver first");
//         wait_for_exit();
//         return;
//     }

//     println!("✅ SUCCESS! Connected to kernel driver");
//     println!("Connection handle: {:?}", handle);
//     println!("\nStep 2: Sending test policy...\n");

    // PHASE-1: Allow reading, block everything else
    // let test_policy = make_policy(
    //     "\\Device\\HarddiskVolume4\\TopSecret\\Saurabh_Gupta_Resume.pdf", // CHANGE THIS TO REAL NT PATH
    //     false,    // folder
    //     1,       // block_read = 0 (ALLOW reading)
    //     1,       // block_write = 1 (BLOCK modifications)
    //     1,       // block_delete = 1 (BLOCK deletion)
    //     1,       // block_rename = 1 (BLOCK rename)
    //     1,       // block_create = 1 (BLOCK new files)
    //     0        // block_all = 0 (not using BlockAll)
    // );

    //  let test_policy = make_policy(
    //     "\\Device\\x\\",
    //     true,    // folder
    //     0,       // block_read = 0 (ALLOW reading)
    //     0,       // block_write = 1 (BLOCK modifications)
    //     0,       // block_delete = 1 (BLOCK deletion)
    //     0,       // block_rename = 1 (BLOCK rename)
    //     1,       // block_create = 1 (BLOCK new files)
    //     0        // block_all = 0 (not using BlockAll)
    // );

//     send_policy(handle, &test_policy, "Phase-1 immutability policy");

//     println!("\n========================================");
//     println!("DLP PHASE-1 ACTIVE");
//     println!("========================================");
//     println!("Protecting: C:\\TopSecret\\");
//     println!("\n✅ ALLOWED Operations:");
//     println!("  • Opening files (double-click)");
//     println!("  • Viewing file contents");
//     println!("  • Reading documents/PDFs");
//     println!("  • Listing directory");
//     println!("\n❌ BLOCKED Operations:");
//     println!("  • Saving/modifying files");
//     println!("  • Deleting files");
//     println!("  • Renaming files");
//     println!("  • Creating new files");
//     println!("  • Copying files (blocked at kernel)");
//     println!("========================================\n");

//     println!("IMPORTANT TEST INSTRUCTIONS:");
//     println!("1. Create folder: C:\\TopSecret\\");
//     println!("2. Put test files inside (e.g., test.txt, test.pdf)");
//     println!("3. Test these operations:");
//     println!("   a. Double-click test.txt → Should OPEN ✅");
//     println!("   b. Try to edit and save → Should FAIL ❌");
//     println!("   c. Try to delete file → Should FAIL ❌");
//     println!("   d. Try to create new file → Should FAIL ❌");
//     println!("\nTo remove protection, use command: remove\n");

//     // Interactive loop
//     loop {
//         print!("> ");
//         io::stdout().flush().unwrap();

//         let mut input = String::new();
//         match io::stdin().read_line(&mut input) {
//             Ok(_) => {
//                 let cmd = input.trim().to_lowercase();

//                 match cmd.as_str() {
//                     "exit" | "quit" | "q" => {
//                         println!("Exiting DLP Agent...");
//                         break;
//                     },
//                     "remove" | "clear" => {
//                         println!("Removing all policies...");
//                         let remove_policy = remove_policy("C:\\TopSecret\\", true);
//                         send_policy(handle, &remove_policy, "Remove protection");
//                         println!("Protection removed. Files are now mutable.");
//                     },
//                     "test" => {
//                         println!("Current protection active:");
//                         println!("• C:\\TopSecret\\ - Immutable (read-only)");
//                         println!("Test by trying to modify files in that folder.");
//                     },
//                     "help" | "?" => {
//                         println!("Available commands:");
//                         println!("  test    - Show current protection status");
//                         println!("  remove  - Remove all protection");
//                         println!("  exit    - Exit program");
//                         println!("  help    - Show this help");
//                     },
//                     "" => continue, // Empty input
//                     _ => {
//                         println!("Unknown command. Type 'help' for available commands.");
//                     }
//                 }
//             },
//             Err(e) => {

//                 println!("Error reading input: {}", e);
//                 break;
//             }
//         }
//     }

//     println!("DLP Agent terminated.");
//     wait_for_exit();
// }

// main.rs - DLP Rust Agent (Minimal, Correct, Kernel-Safe)

// pub mod fltlib;

// use fltlib::*;
// use windows_sys::Win32::{
//     Foundation::*,
//     Storage::FileSystem::*,
//     System::SystemServices::*,
//     UI::Shell::ShellExecuteW,
//     UI::WindowsAndMessaging::SW_SHOW,
//     Security::*,
//     System::Threading::*,
// };

// use std::ptr;
// use std::io::{self,Write};
// use std::os::windows::ffi::{OsStrExt, OsStringExt};

// // --------------------------------------------------
// // Utility
// // --------------------------------------------------

// fn wide(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(Some(0)).collect()
// }

// // --------------------------------------------------
// // Admin elevation
// // --------------------------------------------------

// fn is_elevated() -> bool {
//     unsafe {
//         let mut token: HANDLE = 0;
//         let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
//         let mut size: u32 = 0;

//         if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
//             return false;
//         }

//         if GetTokenInformation(
//             token,
//             TokenElevation,
//             &mut elevation as *mut _ as *mut _,
//             std::mem::size_of::<TOKEN_ELEVATION>() as u32,
//             &mut size,
//         ) != 0 {
//             elevation.TokenIsElevated != 0
//         } else {
//             false
//         }
//     }
// }

// fn restart_as_admin() {
//     let exe = std::env::current_exe().unwrap();
//     let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
//     let verb = wide("runas");

//     unsafe {
//         ShellExecuteW(
//             0,
//             verb.as_ptr(),
//             exe_w.as_ptr(),
//             ptr::null(),
//             ptr::null(),
//             SW_SHOW,
//         );
//     }

//     std::process::exit(0);
// }

// // --------------------------------------------------
// // Disk detection (ONLY HarddiskVolumeX)
// // --------------------------------------------------

// fn list_harddisk_volumes() -> Vec<String> {
//     let mut result = Vec::new();

//     unsafe {
//         let mask = GetLogicalDrives();

//         for i in 0..26 {
//             if (mask & (1 << i)) != 0 {
//                 let letter = (b'A' + i as u8) as char;
//                 let dos = format!("{}:", letter);
//                 let dos_w: Vec<u16> = dos.encode_utf16().chain(Some(0)).collect();

//                 let mut buffer = vec![0u16; 512];

//                 let len = QueryDosDeviceW(
//                     dos_w.as_ptr(),
//                     buffer.as_mut_ptr(),
//                     buffer.len() as u32,
//                 );

//                 if len != 0 {
//                     let device = String::from_utf16_lossy(
//                         &buffer[..buffer.iter().position(|&x| x == 0).unwrap()]
//                     );

//                     if device.starts_with("\\Device\\HarddiskVolume") {
//                         result.push(device);
//                     }
//                 }
//             }
//         }
//     }

//     result
// }

// // --------------------------------------------------
// // Policy structure
// // --------------------------------------------------

// #[repr(C)]
// #[derive(Clone, Copy)]
// struct FilePolicy {
//     pub path: [u16; 260],
//     pub is_folder: u8,
//     pub block_read: u8,
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_all: u8,
//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

// fn make_policy(
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8,
// ) -> FilePolicy {
//     let mut p = FilePolicy {
//         path: [0; 260],
//         is_folder: if is_folder { 1 } else { 0 },
//         block_read,
//         block_write,
//         block_delete,
//         block_rename,
//         block_create,
//         block_all,
//         timestamp: std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .unwrap_or_default()
//             .as_secs(),
//         added_by: [0; 64],
//         reserved: [0; 8],
//     };

//     let wide_path: Vec<u16> = path.encode_utf16().collect();
//     let len = wide_path.len().min(259);
//     p.path[..len].copy_from_slice(&wide_path[..len]);

//     if is_folder && len > 0 && p.path[len - 1] != b'\\' as u16 {
//         p.path[len] = b'\\' as u16;
//     }

//     p
// }

// // --------------------------------------------------
// // Kernel communication
// // --------------------------------------------------

// fn connect_to_kernel() -> Result<HANDLE, String> {
//     let mut handle: HANDLE = 0;
//     let port = wide("\\DlpPort");

//     let status = unsafe {
//         FilterConnectCommunicationPort(
//             port.as_ptr(),
//             0,
//             ptr::null(),
//             0,
//             ptr::null_mut(),
//             &mut handle,
//         )
//     };

//     if status != 0 {
//         Err(format!("Kernel connect failed: NTSTATUS 0x{:X}", status))
//     } else {
//         Ok(handle)
//     }
// }

// fn send_policy(handle: HANDLE, policy: &FilePolicy) {
//     let mut returned = 0u32;

//     let status = unsafe {
//         FilterSendMessage(
//             handle,
//             policy as *const _ as _,
//             std::mem::size_of::<FilePolicy>() as u32,
//             ptr::null_mut(),
//             0,
//             &mut returned,
//         )
//     };

//     if status == 0 {
//         println!("✅ Policy sent successfully");
//     } else {
//         println!("❌ Failed to send policy: NTSTATUS 0x{:X}", status);
//     }
// }

// // --------------------------------------------------
// // Main
// // --------------------------------------------------

// fn main() {
//     println!("🚀 DLP Rust Agent (Minimal)");

//     if !is_elevated() {
//         println!("⚠️  Restarting as Administrator...");
//         restart_as_admin();
//     }

//     let handle = match connect_to_kernel() {
//         Ok(h) => {
//             println!("✅ Connected to kernel driver");
//             h
//         }
//         Err(e) => {
//             println!("❌ {}", e);
//             return;
//         }
//     };

//     println!("\n🔍 Detected disks:");

//     let disks = list_harddisk_volumes();

//     if disks.is_empty() {
//         println!("❌ No HarddiskVolume found");
//         return;
//     }

//     for d in &disks {
//         println!("{}", d);
//     }

//     // Automatically pick first disk
//     let selected_path = format!("{}\\", disks[0]);
//     println!("\n🔒 Applying READ-ONLY policy on:");
//     println!("{}", selected_path);

//     let policy = make_policy(
//         &selected_path,
//         true,
//         0, // allow read
//         1, // block write
//         1, // block delete
//         1, // block rename
//         1, // block create
//         0,
//     );

//     send_policy(handle, &policy);

//     println!("\nDLP policy active. Press Enter to exit.");
//     let _ = io::stdin().read_line(&mut String::new());
// }




// new one which is working tested

// pub mod fltlib;
// use fltlib::*;
// use windows_sys::Win32::Foundation::*;
// use std::ptr;
// use std::collections::HashMap;
// use std::sync::Mutex;
// use once_cell::sync::Lazy;
// // use ctrlc;

// fn wide(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(Some(0)).collect()
// }

// // Global policy registry
// type PolicyKey = String; // Normalized NT path (folders end with \)
// static ACTIVE_POLICIES: Lazy<Mutex<HashMap<PolicyKey, FilePolicy>>> = Lazy::new(|| {
//     Mutex::new(HashMap::new())
// });

// #[repr(C)]
// #[derive(Clone, Copy)]
// struct FilePolicy {
//     pub path: [u16; 260],
//     pub is_folder: u8,
//     pub block_read: u8,
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_all: u8,
//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

// /// Normalize NT path consistently
// /// - Converts to UTF-16
// /// - For folders: ensures trailing backslash
// /// - Truncates to 259 characters (leaving room for optional trailing backslash)
// fn normalize_nt_path(path: &str, is_folder: bool) -> (Vec<u16>, String) {
//     let mut normalized = String::from(path);

//     // Trim and normalize
//     normalized = normalized.trim().replace('/', "\\");

//     // Ensure proper NT path format
//     if !normalized.starts_with("\\Device\\") {
//         // If not already an NT path, assume it's already normalized from user input
//         // (In production, you'd want to validate this more thoroughly)
//     }

//     // For folders, ensure trailing backslash
//     if is_folder && !normalized.ends_with('\\') {
//         normalized.push('\\');
//     }

//     // Convert to UTF-16
//     let wide_str: Vec<u16> = normalized.encode_utf16().collect();

//     (wide_str, normalized)
// }

// fn make_policy(
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> (FilePolicy, String) {
//     let (wide_str, normalized_path) = normalize_nt_path(path, is_folder);

//     let mut p = FilePolicy {
//         path: [0; 260],
//         is_folder: if is_folder { 1 } else { 0 },
//         block_read,
//         block_write,
//         block_delete,
//         block_rename,
//         block_create,
//         block_all,
//         timestamp: std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .unwrap()
//             .as_secs(),
//         added_by: [0; 64],
//         reserved: [0; 8],
//     };

//     // Copy the normalized path
//     let copy_len = wide_str.len().min(259);
//     p.path[..copy_len].copy_from_slice(&wide_str[..copy_len]);

//     (p, normalized_path)
// }

// /// Remove a policy by sending zeroed flags
// fn remove_policy_internal(handle: HANDLE, path: &str, is_folder: bool) -> bool {
//     let (remove_policy, normalized_path) = make_policy(path, is_folder, 0, 0, 0, 0, 0, 0);
//     send_policy(handle, &remove_policy, &format!("Remove policy: {}", normalized_path))
// }

// /// Apply a policy with proper update logic
// fn apply_policy(
//     handle: HANDLE,
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> bool {
//     let (new_policy, normalized_path) = make_policy(
//         path, is_folder,
//         block_read, block_write, block_delete,
//         block_rename, block_create, block_all
//     );

//     // Check if policy already exists
//     let mut policies = ACTIVE_POLICIES.lock().unwrap();

//     if let Some(existing_policy) = policies.get(&normalized_path) {
//         // Policy exists - remove it first
//         println!("⚠️ Policy exists for {}, removing old policy...", normalized_path);

//         let (remove_policy, _) = make_policy(path, is_folder, 0, 0, 0, 0, 0, 0);
//         if !send_policy(handle, &remove_policy, &format!("Remove old policy: {}", normalized_path)) {
//             println!("❌ Failed to remove old policy");
//             return false;
//         }
//     }

//     // Send new policy
//     let description = if policies.contains_key(&normalized_path) {
//         format!("Update policy: {}", normalized_path)
//     } else {
//         format!("Add policy: {}", normalized_path)
//     };

//     if send_policy(handle, &new_policy, &description) {
//         // Store in registry
//         policies.insert(normalized_path.clone(), new_policy);
//         true
//     } else {
//         false
//     }
// }

// /// Remove a policy from both kernel and registry
// fn remove_policy(handle: HANDLE, path: &str, is_folder: bool) -> bool {
//     let (_, normalized_path) = normalize_nt_path(path, is_folder);
//     let mut policies = ACTIVE_POLICIES.lock().unwrap();

//     if policies.contains_key(&normalized_path) {
//         if remove_policy_internal(handle, path, is_folder) {
//             policies.remove(&normalized_path);
//             println!("✅ Removed policy for: {}", normalized_path);
//             true
//         } else {
//             println!("❌ Failed to remove policy for: {}", normalized_path);
//             false
//         }
//     } else {
//         println!("⚠️ No active policy found for: {}", normalized_path);
//         false
//     }
// }

// /// Cleanup all policies on exit
// fn cleanup_all_policies(handle: HANDLE) {
//     println!("🧹 Cleaning up all active policies...");

//     let mut policies = ACTIVE_POLICIES.lock().unwrap();
//     let count = policies.len();

//     if count == 0 {
//         println!("✅ No active policies to clean up");
//         return;
//     }

//     println!("📋 Removing {} active policies...", count);

//     let mut successful = 0;
//     let mut failed = 0;

//     // Create a copy of keys to avoid borrowing issues
//     let keys: Vec<(String, bool)> = policies.iter()
//         .map(|(path, policy)| (path.clone(), policy.is_folder == 1))
//         .collect();

//     for (path, is_folder) in keys {
//         if remove_policy_internal(handle, &path, is_folder) {
//             successful += 1;
//         } else {
//             failed += 1;
//         }
//     }

//     // Clear the registry
//     policies.clear();

//     println!("✅ Cleanup complete:");
//     println!("   Successful removals: {}", successful);
//     println!("   Failed removals: {}", failed);

//     if failed > 0 {
//         println!("⚠️ WARNING: Some policies may still be active in kernel!");
//     }
// }

// fn send_policy(handle: HANDLE, policy: &FilePolicy, description: &str) -> bool {
//     let mut returned: u32 = 0;
//     let status = unsafe {
//         FilterSendMessage(
//             handle,
//             policy as *const _ as _,
//             std::mem::size_of::<FilePolicy>() as u32,
//             ptr::null_mut(),
//             0,
//             &mut returned,
//         )
//     };

//     if status == 0 {
//         println!("✅ {}", description);
//         true
//     } else {
//         println!("❌ Failed to send {}: NTSTATUS=0x{:X}", description, status);
//         false
//     }
// }

// /// Display current active policies
// fn list_policies() {
//     let policies = ACTIVE_POLICIES.lock().unwrap();

//     println!("📋 Active Policies ({}):", policies.len());
//     println!("{:-<80}", "");

//     for (path, policy) in policies.iter() {
//         let policy_type = if policy.is_folder == 1 { "Folder" } else { "File " };
//         println!("{}: {}", policy_type, path);
//         println!("  Flags: R{} W{} D{} RN{} C{} A{}",
//             policy.block_read,
//             policy.block_write,
//             policy.block_delete,
//             policy.block_rename,
//             policy.block_create,
//             policy.block_all
//         );
//         println!();
//     }
// }

// fn main() {
//     println!("DLP PHASE-1 - NT PATHS ONLY");
//     println!("============================\n");

//     println!("Connecting to kernel driver...");

//     let mut handle: HANDLE = 0;
//     let port = wide("\\DlpPort");

//     let status = unsafe {
//         FilterConnectCommunicationPort(
//             port.as_ptr(),
//             0,
//             ptr::null(),
//             0,
//             ptr::null_mut(),
//             &mut handle,
//         )
//     };

//     if status != 0 {
//         println!("❌ Failed to connect to kernel: NTSTATUS=0x{:X}", status);
//         return;
//     }

//     println!("✅ Connected to kernel driver!\n");

//     // Setup Ctrl+C handler for cleanup
//     let handle_for_ctrlc = handle;
//     ctrlc::set_handler(move || {
//         println!("\n🛑 Ctrl+C received, cleaning up...");
//         cleanup_all_policies(handle_for_ctrlc);
//         std::process::exit(0);
//     }).expect("Error setting Ctrl+C handler");

//     println!("IMPORTANT: Using NT paths only\n");
//     println!("Example NT paths (use DebugView to see real paths):");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\TopSecret\\\\");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\Users\\\\Test\\\\file.txt");
//     println!();

//     // TEST: Apply some initial policies
//     println!("1. Setting immutability for NT folder:");
//     apply_policy(
//         handle,
//         "\\Device\\HarddiskVolume4\\Agentstarts",
//         true,    // folder
//         0,       // block_read = 0 (ALLOW reading)
//         1,       // block_write = 1 (BLOCK modifications)
//         1,       // block_delete = 1 (BLOCK deletion)
//         1,       // block_rename = 1 (BLOCK rename)
//         1,       // block_create = 1 (BLOCK new files)
//         0        // block_all = 0
//     );

//     println!("\n2. Protecting specific file: ");
//     apply_policy(
//         handle,
//         "\\Device\\HarddiskVolume4\\TopSecret\\Saurabh_Gupta_Resum.pdf",
//         false,   // file
//         0,       // block_read = 0
//         0,       // block_write = 1
//         0,       // block_delete = 1
//         0,       // block_rename = 1
//         0,       // block_create = 0 (N/A for files)
//         1        // block_all = 0
//     );

//     println!("\n============================");
//     println!("PHASE-1 ACTIVE");
//     println!("============================");
//     println!("Will BLOCK:");
//     println!("  • Write/modify");
//     println!("  • Delete");
//     println!("  • Rename");
//     println!("  • Create new files");
//     println!("  • Memory-mapped writes (PDF/Office)");
//     println!("\nWill ALLOW:");
//     println!("  • Read/open/view");
//     println!("  • Directory listing");
//     println!("============================\n");

//     println!("Commands:");
//     println!("  test        - Send test paths");
//     println!("  list        - Show active policies");
//     println!("  apply       - Apply new policy (interactive)");
//     println!("  update      - Update existing policy (interactive)");
//     println!("  remove <path> - Remove policy for path");
//     println!("  cleanup     - Remove all policies");
//     println!("  exit        - Quit and cleanup");

//     loop {
//         print!("> ");
//         std::io::Write::flush(&mut std::io::stdout()).unwrap();

//         let mut input = String::new();
//         std::io::stdin().read_line(&mut input).unwrap();
//         let input = input.trim();
//         let lower_input = input.to_lowercase();

//         match lower_input.as_str() {
//             "exit" => {
//                 println!("Exiting...");
//                 cleanup_all_policies(handle);
//                 break;
//             },
//             "test" => {
//                 println!("Test: Applying sample policy...");
//                 apply_policy(
//                     handle,
//                     "\\Device\\HarddiskVolume4\\TestFolder",
//                     true,
//                     0, 1, 1, 1, 1, 0
//                 );
//             },
//             "list" => {
//                 list_policies();
//             },
//             "apply" | "update" => {
//                 println!("Enter NT path:");
//                 let mut path = String::new();
//                 std::io::stdin().read_line(&mut path).unwrap();
//                 let path = path.trim();

//                 println!("Is folder? (y/n):");
//                 let mut is_folder = String::new();
//                 std::io::stdin().read_line(&mut is_folder).unwrap();
//                 let is_folder = is_folder.trim().to_lowercase() == "y";

//                 println!("Block read? (0/1):");
//                 let mut block_read = String::new();
//                 std::io::stdin().read_line(&mut block_read).unwrap();
//                 let block_read = block_read.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block write? (0/1):");
//                 let mut block_write = String::new();
//                 std::io::stdin().read_line(&mut block_write).unwrap();
//                 let block_write = block_write.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block delete? (0/1):");
//                 let mut block_delete = String::new();
//                 std::io::stdin().read_line(&mut block_delete).unwrap();
//                 let block_delete = block_delete.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block rename? (0/1):");
//                 let mut block_rename = String::new();
//                 std::io::stdin().read_line(&mut block_rename).unwrap();
//                 let block_rename = block_rename.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block create? (0/1):");
//                 let mut block_create = String::new();
//                 std::io::stdin().read_line(&mut block_create).unwrap();
//                 let block_create = block_create.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block all? (0/1):");
//                 let mut block_all = String::new();
//                 std::io::stdin().read_line(&mut block_all).unwrap();
//                 let block_all = block_all.trim().parse::<u8>().unwrap_or(0);

//                 apply_policy(
//                     handle,
//                     path,
//                     is_folder,
//                     block_read,
//                     block_write,
//                     block_delete,
//                     block_rename,
//                     block_create,
//                     block_all
//                 );
//             },
//             cmd if cmd.starts_with("remove ") => {
//                 let path = &cmd[7..].trim();
//                 println!("Removing policy for: {}", path);

//                 println!("Is folder? (y/n):");
//                 let mut is_folder = String::new();
//                 std::io::stdin().read_line(&mut is_folder).unwrap();
//                 let is_folder = is_folder.trim().to_lowercase() == "y";

//                 remove_policy(handle, path, is_folder);
//             },
//             "cleanup" => {
//                 cleanup_all_policies(handle);
//             },
//             _ => {
//                 println!("Available commands:");
//                 println!("  test        - Send test paths");
//                 println!("  list        - Show active policies");
//                 println!("  apply       - Apply new policy");
//                 println!("  update      - Update existing policy");
//                 println!("  remove <path> - Remove policy for path");
//                 println!("  cleanup     - Remove all policies");
//                 println!("  exit        - Quit and cleanup");
//             },
//         }
//     }

//     println!("DLP Agent terminated.");
// }




/* for new implementaion for browisng thing */
// STEP 1: Filesystem Index modules (NO kernel dependencies)
// mod fs_index;
// mod path_normalizer;
// mod filesystem_scanner;
// mod query_interface;

// use fs_index::FilesystemIndex;
// use filesystem_scanner::FileSystemScanner;
// use query_interface::QueryInterface;

// use std::sync::Arc;

// use crate::query_interface::QueryResponse;

// fn main() {
//     println!("DLP AGENT - STEP 1: Filesystem Index Only");
//     println!("===========================================\n");

//     // Create global filesystem index
//     let index = FilesystemIndex::new();

//     // Create scanner with lazy loading
//     let scanner = FileSystemScanner::new(index.clone());

//     // Create query interface
//     let query = QueryInterface::new(index.clone());

//     // STEP 1: Initialize drives only (NO full scan)
//     match scanner.initialize_drives() {
//         Ok(drive_count) => {
//             println!("\n✅ STEP 1 COMPLETE: Filesystem Index Ready");
//             println!("   • Drives initialized: {}", drive_count);
//             println!("   • Index nodes: {}", index.node_count());
//             println!("   • Ready for lazy directory expansion\n");

//             // Show current state
//             show_index_state(&query);

//             // Demonstrate lazy expansion
//             demonstrate_lazy_expansion(&scanner, &query);
//         }
//         Err(e) => {
//             println!("❌ Failed to initialize drives: {}", e);
//             println!("⚠️  Continuing with empty index...");
//         }
//     }

//     println!("\n===========================================");
//     println!("STEP 1 Complete - Agent understands filesystem");
//     println!("Next: Admin Server can query via IDs only");
//     println!("===========================================\n");

//     // Note: Kernel policy logic would be separate
//     // This is pure STEP 1 - filesystem knowledge only
// }

// /// Show current index state
// fn show_index_state(query: &QueryInterface) {
//     println!("📊 Current Index State:");

//     // Get drives
//     if let QueryResponse::Drives(drives) = query.get_drives() {
//         println!("   Drives ({}):", drives.len());
//         for drive in drives {
//             println!("     • {} (ID: {})", drive.display_name, drive.node_id);
//         }
//     }

//     // Get stats
//     if let QueryResponse::Stats(stats) = query.get_stats() {
//         println!("   {}", stats);
//     }
// }

// /// Demonstrate lazy directory expansion
// fn demonstrate_lazy_expansion(scanner: &FileSystemScanner, query: &QueryInterface) {
//     println!("🔍 Lazy Expansion Demo:");

//     // Get first drive to expand
//     if let QueryResponse::Drives(drives) = query.get_drives() {
//         if !drives.is_empty() {
//             let first_drive_id = drives[0].node_id;

//             // Expand drive (load root directory)
//             match scanner.expand_directory(first_drive_id) {
//                 Ok(child_count) => {
//                     println!("   ✅ Expanded drive ID {} -> {} children",
//                         first_drive_id, child_count);

//                     // Show some children
//                     if let QueryResponse::Nodes(children) = query.list_children(first_drive_id) {
//                         let sample_count = children.len().min(5);
//                         println!("   Sample children ({} total):", children.len());
//                         for child in children.iter().take(sample_count) {
//                             println!("     • {} (ID: {}, Type: {})",
//                                 child.name, child.id, child.entry_type);
//                         }
//                         if children.len() > sample_count {
//                             println!("     ... and {} more", children.len() - sample_count);
//                         }
//                     }
//                 }
//                 Err(e) => {
//                     println!("   ❌ Failed to expand drive: {}", e);
//                 }
//             }
//         }
//     }

//     println!("\n💡 Key Features:");
//     println!("   1. No full-disk scanning");
//     println!("   2. Lazy directory expansion on demand");
//     println!("   3. Path → ID mapping for quick lookups");
//     println!("   4. Admin sees only IDs, never NT paths");
//     println!("   5. Ready for Admin Server queries");
// }

/*  Step 2:  */
// mod fs_index;
// mod path_normalizer;
// mod filesystem_scanner;
// mod query_interface;

// // STEP 2: Communication Layer modules
// mod comms;

// use fs_index::FilesystemIndex;
// use filesystem_scanner::FileSystemScanner;
// use query_interface::QueryInterface;

// use std::sync::Arc;

// fn main() {
//     println!("DLP AGENT - STEP 1 + STEP 2 DEMO");
//     println!("================================\n");

//     // ==============================
//     // STEP 1: Filesystem Index
//     // ==============================
//     println!("🧱 STEP 1: Building Filesystem Index...");

//     let index = FilesystemIndex::new();
//     let scanner = FileSystemScanner::new(index.clone());
//     let query = QueryInterface::new(index.clone());

//     // Initialize drives only (no full scan)
//     match scanner.initialize_drives() {
//         Ok(drive_count) => {
//             println!("✅ STEP 1 Complete: {} drives ready", drive_count);
//         }
//         Err(e) => {
//             println!("⚠️  STEP 1 Warning: {}", e);
//             println!("   Continuing with mock data for STEP 2 demo...");
//         }
//     }

//     // ==============================
//     // STEP 2: Communication Layer
//     // ==============================
//     println!("\n📡 STEP 2: Initializing Admin ↔ Agent Communication...");

//     // Initialize STEP 2
//     let (api_server, transport_config) = comms::init_step2(
//         Arc::new(scanner),
//         Arc::new(query),
//     );

//     println!("✅ STEP 2 Complete: Communication layer ready");
//     println!("   API endpoints designed and protocol defined");
//     println!("   Ready for Admin Server integration");

//     // ==============================
//     // STEP 2 DEMONSTRATION
//     // ==============================
//     println!("\n🔍 STEP 2 DEMONSTRATION:");
//     println!("   Showing how Admin would interact with Agent via IDs only");

//     demonstrate_admin_agent_communication(&api_server);

//     println!("\n========================================");
//     println!("STEP 2 SUCCESS CRITERIA MET:");
//     println!("1. ✅ Admin ↔ Agent protocol defined");
//     println!("2. ✅ Query API Server implemented");
//     println!("3. ✅ ID-based communication only");
//     println!("4. ✅ No NT paths exposed");
//     println!("5. ✅ No filesystem writes");
//     println!("6. ✅ No kernel calls");
//     println!("7. ✅ Read-only operations only");
//     println!("8. ✅ Ready for Admin Server integration");
//     println!("========================================\n");

//     println!("🎯 NEXT STEPS:");
//     println!("   • Admin Server can now connect via HTTP/WebSocket");
//     println!("   • Admin UI will consume this API (STEP 3)");
//     println!("   • Policies will be applied by ID (STEP 4)");
// }

// /// Demonstrate Admin ↔ Agent communication
// fn demonstrate_admin_agent_communication(api_server: &comms::QueryApiServer) {
//     use comms::AdminRequest;

//     println!("\n📤 Admin → Agent: GetDrives");
//     match api_server.handle_request(AdminRequest::GetDrives) {
//         comms::AgentResponse::Drives { drives } => {
//             println!("📥 Agent → Admin: {} drives", drives.len());
//             for drive in drives {
//                 println!("   • {} (ID: {}) - {}",
//                     drive.name, drive.id, drive.drive_letter);
//             }
//         }
//         response => println!("   ❌ Unexpected response: {:?}", response),
//     }

//     // Simulate Admin expanding C: drive
//     println!("\n📤 Admin → Agent: ExpandNode {{ node_id: 2 }}");
//     match api_server.handle_request(AdminRequest::ExpandNode { node_id: 2 }) {
//         comms::AgentResponse::Expanded { node_id, node_name, new_children, total_children } => {
//             println!("📥 Agent → Admin: Expanded '{}' (ID: {})", node_name, node_id);
//             println!("   • New children loaded: {}", new_children);
//             println!("   • Total children: {}", total_children);
//         }
//         comms::AgentResponse::Error { code, message, .. } => {
//             println!("📥 Agent → Admin: ERROR {}: {}", code, message);
//             println!("   ⚠️  This is expected - node ID 2 doesn't exist yet");
//             println!("   In production, Admin would get real drive IDs from GetDrives");
//         }
//         response => println!("   ❌ Unexpected response: {:?}", response),
//     }

//     // Simulate Admin getting node info
//     println!("\n📤 Admin → Agent: GetNode {{ node_id: 1 }}");
//     match api_server.handle_request(AdminRequest::GetNode { node_id: 1 }) {
//         comms::AgentResponse::Node { node } => {
//             println!("📥 Agent → Admin: Node info for ID {}", node.id);
//             println!("   • Name: {}", node.name);
//             println!("   • Type: {}", node.node_type);
//             println!("   • Has children: {}", node.has_children);
//         }
//         response => println!("   Response: {:?}", response),
//     }

//     // Simulate Admin getting stats
//     println!("\n📤 Admin → Agent: GetStats");
//     match api_server.handle_request(AdminRequest::GetStats) {
//         comms::AgentResponse::Stats { stats } => {
//             println!("📥 Agent → Admin: System stats");
//             println!("   • Total nodes: {}", stats.total_nodes);
//             println!("   • Total drives: {}", stats.total_drives);
//             println!("   • Memory usage: {} bytes", stats.memory_usage_bytes);
//             println!("   • Scan state: {}", stats.scan_state);
//         }
//         response => println!("   Response: {:?}", response),
//     }

//     // Simulate ping
//     println!("\n📤 Admin → Agent: Ping");
//     match api_server.handle_request(AdminRequest::Ping) {
//         comms::AgentResponse::Pong { timestamp, version } => {
//             println!("📥 Agent → Admin: Pong");
//             println!("   • Timestamp: {}", timestamp);
//             println!("   • Version: {}", version);
//         }
//         response => println!("   Response: {:?}", response),
//     }

//     println!("\n💡 KEY POINTS DEMONSTRATED:");
//     println!("   1. Admin only uses IDs (no paths)");
//     println!("   2. Agent responds with metadata only (no NT paths)");
//     println!("   3. All operations are read-only");
//     println!("   4. Communication is stateless and deterministic");
//     println!("   5. Error handling is consistent and informative");
// }

/*  Step 3  */
/*  Step 1 + Step 2 + Step 3  */
// mod fs_index;
// mod path_normalizer;
// mod filesystem_scanner;
// mod query_interface;

// // STEP 2: Communication Layer modules
// mod comms;

// // STEP 3: Explorer UI modules
// mod ui;
// mod policy;
// use fs_index::FilesystemIndex;
// use filesystem_scanner::FileSystemScanner;
// use query_interface::QueryInterface;

// use std::sync::Arc;

// fn main() {
//     println!("DLP AGENT - STEP 1 + STEP 2 + STEP 3 DEMO");
//     println!("==========================================\n");

//     // ==============================
//     // STEP 1: Filesystem Index
//     // ==============================
//     println!("🧱 STEP 1: Building Filesystem Index...");

//     let index = FilesystemIndex::new();
//     let scanner = FileSystemScanner::new(index.clone());
//     let query = QueryInterface::new(index.clone());

//     // Initialize drives only (no full scan)
//     match scanner.initialize_drives() {
//         Ok(drive_count) => {
//             println!("✅ STEP 1 Complete: {} drives ready", drive_count);
//         }
//         Err(e) => {
//             println!("⚠️  STEP 1 Warning: {}", e);
//             println!("   Using mock data for demonstration...");
//         }
//     }

//     // ==============================
//     // STEP 2: Communication Layer
//     // ==============================
//     println!("\n📡 STEP 2: Initializing Admin ↔ Agent Communication...");

//     // Initialize STEP 2
//     let (api_server, _) = comms::init_step2(
//         Arc::new(scanner),
//         Arc::new(query),
//     );

//     println!("✅ STEP 2 Complete: Communication layer ready");

//     // ==============================
//     // STEP 3: Explorer UI Behavior
//     // ==============================
//     println!("\n🎨 STEP 3: Initializing Explorer UI Behavior...");

//     // Initialize STEP 3
//     let explorer = ui::init_step3(api_server.clone());

//     // Demonstrate STEP 3 functionality
//     demonstrate_step3_ui_behavior(&explorer);

//     println!("\n==========================================");
//     println!("STEP 3 SUCCESS CRITERIA MET:");
//     println!("1. ✅ Explorer UI state model implemented");
//     println!("2. ✅ Interaction rules defined");
//     println!("3. ✅ Selection → 'Protect this' flow ready");
//     println!("4. ✅ Search is LOCAL ONLY (clearly indicated)");
//     println!("5. ✅ No NT paths exposed to UI");
//     println!("6. ✅ No kernel calls (STEP 4 will handle)");
//     println!("7. ✅ Admin sees ONLY IDs");
//     println!("==========================================\n");

//     println!("🎯 NEXT STEPS:");
//     println!("   • STEP 4: Policy Engine (ID → NT path → kernel)");
//     println!("   • STEP 5: Real networking (HTTP/WebSocket)");
//     println!("   • STEP 6: Filesystem watchers");
// }

// /// Demonstrate STEP 3 UI behavior
// fn demonstrate_step3_ui_behavior(explorer: &ui::ExplorerController) {
//     println!("\n🔍 STEP 3 DEMONSTRATION:");
//     println!("   Showing Explorer UI behavior using STEP 2 APIs");

//     // Initialize explorer (load drives)
//     match explorer.initialize() {
//         Ok(drive_ids) => {
//             println!("\n✅ Explorer initialized with {} drives", drive_ids.len());

//             if !drive_ids.is_empty() {
//                 let first_drive_id = drive_ids[0];

//                 // Demonstrate folder click (selects, doesn't expand)
//                 println!("\n📝 Example 1: Folder Click (Selects, doesn't expand)");
//                 explorer.interaction_engine().handle_drive_click(
//                     first_drive_id,
//                     "Local Disk",
//                     "C:",
//                     true
//                 );

//                 // Demonstrate expand click
//                 println!("\n📝 Example 2: Expand Click (Shows spinner, calls API)");
//                 match explorer.interaction_engine().handle_expand_click(first_drive_id, "C:") {
//                     Ok(_) => {
//                         // Load children after expansion
//                         match explorer.load_children(first_drive_id) {
//                             Ok(children) => {
//                                 println!("   Loaded {} children", children.len());
//                                 if !children.is_empty() {
//                                     let first_child = &children[0];

//                                     // Demonstrate file click
//                                     println!("\n📝 Example 3: File Click (Shows metadata)");
//                                     explorer.interaction_engine().handle_file_click(
//                                         first_child.node_id,
//                                         &first_child.name,
//                                         first_child.is_accessible
//                                     );

//                                     // Demonstrate "Mark for Protection"
//                                     println!("\n📝 Example 4: Mark for Protection (STEP 4 preparation)");
//                                     explorer.interaction_engine().handle_mark_for_protection(
//                                         first_child.node_id,
//                                         &first_child.node_type,
//                                         &first_child.name,
//                                         None, // No size for folders
//                                         1700000000,
//                                     );
//                                 }
//                             }
//                             Err(e) => println!("❌ Failed to load children: {}", e),
//                         }
//                     }
//                     Err(e) => println!("❌ Expansion failed: {}", e),
//                 }

//                 // Demonstrate search (LOCAL ONLY)
//                 println!("\n📝 Example 5: Local Search (Expanded nodes only)");
//                 match explorer.interaction_engine().handle_search(first_drive_id, "Users", None) {
//                     Ok(results) => println!("   Found {} matches (local search only)", results.len()),
//                     Err(e) => println!("   Search error: {}", e),
//                 }

//                 // Demonstrate collapse
//                 println!("\n📝 Example 6: Collapse Click");
//                 match explorer.interaction_engine().handle_collapse_click(first_drive_id, "C:") {
//                     Ok(_) => println!("   Collapsed successfully"),
//                     Err(e) => println!("   Collapse error: {}", e),
//                 }
//             }
//         }
//         Err(e) => println!("❌ Failed to initialize explorer: {}", e),
//     }

//     // Show UI summary
//     explorer.show_summary();

//     println!("\n💡 KEY STEP 3 PRINCIPLES DEMONSTRATED:");
//     println!("   1. UI maintains its own state (expand/collapse/selection)");
//     println!("   2. All interactions use STEP 2 APIs (IDs only)");
//     println!("   3. Search is clearly marked as LOCAL ONLY");
//     println!("   4. 'Mark for Protection' stores selection for STEP 4");
//     println!("   5. No NT paths exposed to Admin");
//     println!("   6. No kernel calls (pure UI behavior)");
// }

/*  Step 1 + Step 2 + Step 3 + step 4 */

// mod fs_index;
// mod path_normalizer;
// mod filesystem_scanner;
// mod query_interface;

// // STEP 2: Communication Layer modules
// mod comms;
// mod fltlib;
// mod ui;
// mod policy;
// mod networking;

// use fs_index::FilesystemIndex;
// use filesystem_scanner::FileSystemScanner;
// use query_interface::QueryInterface;

// use std::sync::Arc;

// fn main() {
//     println!("DLP AGENT - STEP 1 + STEP 2 + STEP 3 + STEP 4 DEMO");
//     println!("==================================================\n");

//     // ==============================
//     // STEP 1: Filesystem Index
//     // ==============================
//     println!("🧱 STEP 1: Building Filesystem Index...");

//     let index = FilesystemIndex::new();
//     let scanner = FileSystemScanner::new(index.clone());
//     let query = QueryInterface::new(index.clone());

//     // Initialize drives only (no full scan)
//     match scanner.initialize_drives() {
//         Ok(drive_count) => {
//             println!("✅ STEP 1 Complete: {} drives ready", drive_count);
//         }
//         Err(e) => {
//             println!("⚠️  STEP 1 Warning: {}", e);
//             println!("   Using mock data for demonstration...");
//         }
//     }

//     // ==============================
//     // STEP 2: Communication Layer
//     // ==============================
//     println!("\n📡 STEP 2: Initializing Admin ↔ Agent Communication...");

//     // Initialize STEP 2
//     let (api_server, _) = comms::init_step2(
//         Arc::new(scanner),
//         Arc::new(query),
//     );

//     println!("✅ STEP 2 Complete: Communication layer ready");

//     // ==============================
//     // STEP 3: Explorer UI Behavior
//     // ==============================
//     println!("\n🎨 STEP 3: Initializing Explorer UI Behavior...");

//     // Initialize STEP 3
//     let explorer = ui::init_step3(api_server.clone());

//     // Demonstrate STEP 3 functionality
//     demonstrate_step3_ui_behavior(&explorer);

//     println!("\n✅ STEP 3 Complete: Explorer UI ready");

//     // ==============================
//     // STEP 4: Policy Engine
//     // ==============================
//     println!("\n🔐 STEP 4: Initializing Policy Engine...");

//     // Initialize STEP 4
//     let policy_engine = match policy::init_step4(index.clone()) {
//         Ok(engine) => {
//             println!("✅ STEP 4 Complete: Policy Engine ready");
//             engine
//         }
//         Err(e) => {
//             println!("⚠️  STEP 4 Warning: {}", e);
//             println!("   Continuing in simulation mode...");
//             // In production, you might want to handle this differently
//             return;
//         }
//     };

//     // Demonstrate STEP 4 functionality
//     demonstrate_step4_policy_engine(&policy_engine, &explorer);

//     println!("\n==================================================");
//     println!("ALL STEPS COMPLETE:");
//     println!("1. ✅ STEP 1: Filesystem Index (ID-based tree)");
//     println!("2. ✅ STEP 2: Admin ↔ Agent Communication (IDs only)");
//     println!("3. ✅ STEP 3: Explorer UI Behavior (ID-based interaction)");
//     println!("4. ✅ STEP 4: Policy Engine (ID → NT path → kernel)");
//     println!("==================================================\n");

//     println!("🎯 SYSTEM READY:");
//     println!("   • Admin can browse filesystem via IDs");
//     println!("   • Admin can select files/folders to protect");
//     println!("   • Agent resolves IDs to NT paths internally");
//     println!("   • Policies sent to kernel for enforcement");
//     println!("   • Security boundary: Admin never sees NT paths");
//     println!("   • Security boundary: Kernel never sees IDs");
// }

// /// Demonstrate STEP 3 UI behavior
// fn demonstrate_step3_ui_behavior(explorer: &ui::ExplorerController) {
//     println!("\n🔍 STEP 3 DEMONSTRATION:");
//     println!("   Showing Explorer UI behavior using STEP 2 APIs");

//     // Initialize explorer (load drives)
//     match explorer.initialize() {
//         Ok(drive_ids) => {
//             println!("\n✅ Explorer initialized with {} drives", drive_ids.len());

//             if !drive_ids.is_empty() {
//                 let first_drive_id = drive_ids[0];

//                 // Demonstrate folder click (selects, doesn't expand)
//                 println!("\n📝 Example 1: Folder Click (Selects, doesn't expand)");
//                 explorer.interaction_engine().handle_drive_click(
//                     first_drive_id,
//                     "Local Disk",
//                     "C:",
//                     true
//                 );

//                 // Demonstrate expand click
//                 println!("\n📝 Example 2: Expand Click (Shows spinner, calls API)");
//                 match explorer.interaction_engine().handle_expand_click(first_drive_id, "C:") {
//                     Ok(_) => {
//                         // Load children after expansion
//                         match explorer.load_children(first_drive_id) {
//                             Ok(children) => {
//                                 println!("   Loaded {} children", children.len());
//                                 if !children.is_empty() {
//                                     let first_child = &children[0];

//                                     // Demonstrate file click
//                                     println!("\n📝 Example 3: File Click (Shows metadata)");
//                                     explorer.interaction_engine().handle_file_click(
//                                         first_child.node_id,
//                                         &first_child.name,
//                                         first_child.is_accessible
//                                     );

//                                     // Demonstrate "Mark for Protection"
//                                     println!("\n📝 Example 4: Mark for Protection (STEP 4 preparation)");
//                                     explorer.interaction_engine().handle_mark_for_protection(
//                                         first_child.node_id,
//                                         &first_child.node_type,
//                                         &first_child.name,
//                                         None, // No size for folders
//                                         1700000000,
//                                     );
//                                 }
//                             }
//                             Err(e) => println!("❌ Failed to load children: {}", e),
//                         }
//                     }
//                     Err(e) => println!("❌ Expansion failed: {}", e),
//                 }

//                 // Demonstrate search (LOCAL ONLY)
//                 println!("\n📝 Example 5: Local Search (Expanded nodes only)");
//                 match explorer.interaction_engine().handle_search(first_drive_id, "Users", None) {
//                     Ok(results) => println!("   Found {} matches (local search only)", results.len()),
//                     Err(e) => println!("   Search error: {}", e),
//                 }

//                 // Demonstrate collapse
//                 println!("\n📝 Example 6: Collapse Click");
//                 match explorer.interaction_engine().handle_collapse_click(first_drive_id, "C:") {
//                     Ok(_) => println!("   Collapsed successfully"),
//                     Err(e) => println!("   Collapse error: {}", e),
//                 }
//             }
//         }
//         Err(e) => println!("❌ Failed to initialize explorer: {}", e),
//     }

//     // Show UI summary
//     explorer.show_summary();

//     println!("\n💡 KEY STEP 3 PRINCIPLES DEMONSTRATED:");
//     println!("   1. UI maintains its own state (expand/collapse/selection)");
//     println!("   2. All interactions use STEP 2 APIs (IDs only)");
//     println!("   3. Search is clearly marked as LOCAL ONLY");
//     println!("   4. 'Mark for Protection' stores selection for STEP 4");
//     println!("   5. No NT paths exposed to Admin");
//     println!("   6. No kernel calls (pure UI behavior)");
// }

// /// Demonstrate STEP 4 Policy Engine
// fn demonstrate_step4_policy_engine(policy_engine: &policy::PolicyEngine, explorer: &ui::ExplorerController) {
//     println!("\n🔍 STEP 4 DEMONSTRATION:");
//     println!("   Showing Policy Engine flow: Intent → Kernel");

//     // Get stats
//     let stats = policy_engine.get_stats();
//     println!("   Kernel connected: {}", stats.kernel_connected);

//     // Example 1: Create a read-only file protection
//     println!("\n📝 Example 1: Read-only file protection");

//     let file_intent = policy::PolicyIntent::new(
//         100, // Example file ID (would come from UI selection)
//         policy::ProtectionScope::File,
//         policy::ProtectionAction::Block,
//         policy::ProtectionOperations::read_only(),
//         "admin",
//         Some("Protect important document"),
//     );

//     match policy_engine.apply_protection(file_intent.clone()) {
//         Ok(policy_id) => {
//             println!("   ✅ Applied protection (Policy ID: {})", policy_id);
//             println!("   Intent: {}", file_intent.describe());
//         }
//         Err(e) => {
//             println!("   ❌ Failed: {}", e);
//             // Continue with simulation
//         }
//     }

//     // Example 2: Create recursive folder protection
//     println!("\n📝 Example 2: Recursive folder protection");

//     let folder_intent = policy::PolicyIntent::new(
//         200, // Example folder ID
//         policy::ProtectionScope::FolderRecursive,
//         policy::ProtectionAction::Block,
//         policy::ProtectionOperations::full_protection(),
//         "admin",
//         Some("Protect entire project folder"),
//     );

//     match policy_engine.apply_protection(folder_intent.clone()) {
//         Ok(policy_id) => {
//             println!("   ✅ Applied protection (Policy ID: {})", policy_id);
//             println!("   Intent: {}", folder_intent.describe());
//         }
//         Err(e) => {
//             println!("   ❌ Failed: {}", e);
//             // Continue with simulation
//         }
//     }

//     // Example 3: Audit-only protection (monitor)
//     println!("\n📝 Example 3: Audit-only protection (monitor)");

//     let audit_intent = policy::PolicyIntent::new(
//         300, // Example file ID
//         policy::ProtectionScope::File,
//         policy::ProtectionAction::Audit,
//         policy::ProtectionOperations::audit_only(),
//         "admin",
//         Some("Monitor access to sensitive file"),
//     );

//     match policy_engine.apply_protection(audit_intent.clone()) {
//         Ok(policy_id) => {
//             println!("   ✅ Applied audit protection (Policy ID: {})", policy_id);
//             println!("   Intent: {}", audit_intent.describe());
//         }
//         Err(e) => {
//             println!("   ❌ Failed: {}", e);
//             // Continue with simulation
//         }
//     }

//     // Show active policies
//     println!("\n📋 Active Policies:");
//     let active_policies = policy_engine.get_active_policies();
//     println!("   Total: {} policies", active_policies.len());

//     for policy in active_policies.iter().take(3) {
//         println!("   • Policy ID: {} - {}",
//             policy.intent.node_id,
//             policy.intent.describe());
//     }

//     // Show final stats
//     let final_stats = policy_engine.get_stats();
//     println!("\n📊 Policy Engine Stats:");
//     println!("   Total policies: {}", final_stats.total_policies);
//     println!("   Active policies: {}", final_stats.active_policies);
//     println!("   Protected nodes: {}", final_stats.protected_nodes);
//     println!("   Kernel connected: {}", final_stats.kernel_connected);

//     println!("\n💡 KEY STEP 4 PRINCIPLES DEMONSTRATED:");
//     println!("   1. Admin expresses intent (no NT paths)");
//     println!("   2. Agent resolves IDs → NT paths internally");
//     println!("   3. Policies normalized for kernel understanding");
//     println!("   4. Kernel adapter sends binary messages");
//     println!("   5. Policy store tracks active protections");
//     println!("   6. Security boundary: NT paths never leave Agent");
// }

/*  Step 1 + Step 2 + Step 3 + step 4  + step 5*/
// main.rs
mod fs_index;
mod path_normalizer;
mod filesystem_scanner;
mod query_interface;
mod comms;
mod fltlib;
mod ui;
mod policy;
mod networking;
mod kernel;
mod nt_path_resolver;
use fs_index::FilesystemIndex;
use filesystem_scanner::FileSystemScanner;
use query_interface::QueryInterface;

use std::sync::Arc;

use crate::policy::PathResolver;

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("==================================================");
    println!("      ENTERPRISE DLP AGENT - ALL STEPS READY");
    println!("==================================================\n");

    // ==============================
    // STEP 1: Filesystem Index
    // ==============================
    println!("🧱 STEP 1: Building Filesystem Index...");

    let index = Arc::new(FilesystemIndex::new());
    // Create path resolver
    let path_resolver = Arc::new(PathResolver::new(index.clone()));
    let scanner = FileSystemScanner::new(index.clone(), path_resolver.clone());
    let query = QueryInterface::new(index.clone());

    // Initialize drives only (no full scan)
    match scanner.initialize_drives() {
        Ok(drive_count) => {
            println!("✅ STEP 1 Complete: {} drives ready", drive_count);
        }
        Err(e) => {
            println!("⚠️  STEP 1 Warning: {}", e);
            println!("   Using existing index data...");
        }
    }

    // ==============================
    // STEP 2: Communication Layer
    // ==============================
    println!("\n📡 STEP 2: Initializing Admin ↔ Agent Communication...");

    // Initialize STEP 2
    let (api_server, _) = comms::init_step2(Arc::new(scanner), Arc::new(query));

    println!("✅ STEP 2 Complete: Communication layer ready");

    // ==============================
    // STEP 3: Explorer UI Behavior
    // ==============================
    println!("\n🎨 STEP 3: Initializing Explorer UI Behavior...");

    // Initialize STEP 3 (for local testing/demo)
    let explorer = ui::init_step3(api_server.clone());

    // Demonstrate STEP 3 functionality
    demonstrate_step3_ui_behavior(&explorer);

    println!("✅ STEP 3 Complete: Explorer UI logic ready");


    // ==============================
    // STEP 4: Policy Engine
    // ==============================
    println!("\n🔐 STEP 4: Initializing Policy Engine...");
    // Initialize STEP 4

      // Initialize STEP 4 WITH kernel event support for STEP 6
    // Create the kernel event sender early
    let (kernel_event_sender, kernel_event_receiver) = tokio::sync::mpsc::channel(100);

    let policy_engine = match policy::PolicyEngine::new(index.clone(), Some(kernel_event_sender)) {
        Ok(engine) => {
            println!("✅ STEP 4 Complete: Policy Engine ready with kernel connection");
            engine
        }
        Err(e) => {
            println!("⚠️  STEP 4 Warning: {}", e);
            println!("   Creating simulated policy engine...");
            // Create a simple policy engine for demo
            Arc::new(policy::PolicyEngine::new_simulated())
        }
    };

    // ==============================
    // STEP 5: Networking Layer
    // ==============================
    println!("\n🌐 STEP 5: Initializing Networking Layer...");

    // Bind address (default: localhost:8080)
    let bind_address = std::env
        ::var("AGENT_BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|e| format!("Invalid bind address: {}", e))?;

    println!("   Binding to: {}", bind_address);
    println!("   HTTP Server starting...");

    // Initialize and start STEP 5 networking with graceful shutdown handle
    let server_handle = match
        networking::init_step5(api_server.clone(), policy_engine.clone(), bind_address).await
    {
        Ok(handle) => {
            println!("✅ STEP 5 Complete: Networking layer ready"); 
            println!("   • HTTP: http://{}", bind_address);
            println!("   • WebSocket: ws://{}/api/v1/ws", bind_address);
            println!("   • Auth: Optional X-AGENT-TOKEN header");
            Some(handle)
        }
        Err(e) => {
            println!("❌ STEP 5 Failed: {}", e);
            return Err(e);
        }
    };

    // ==============================
    // STEP 6: Kernel Enforcement
    // ==============================
    println!("\n🔧 STEP 6: Initializing Kernel Enforcement...");

    // Get WebSocket server from networking handle
    let ws_server = server_handle.as_ref().unwrap().ws_server();

     // Initialize and start kernel event bridge
    let (kernel_event_bridge, kernel_event_sender) = kernel::init_step6(ws_server.clone());
    
        // ✅ CRITICAL FIX: Use the public method to attach event sender
        policy_engine.attach_kernel_event_sender((kernel_event_sender));
        println!("✅ PolicyEngine updated with kernel event support");

        // Start kernel event bridge in background
        let bridge_handle = tokio::spawn(async move {
            kernel_event_bridge.start().await;
        });

    // Recreate PolicyEngine with kernel events for STEP 6
    println!("🔄 Updating Policy Engine with kernel event support...");
    println!("✅ STEP 6 Complete: Kernel enforcement ready");
    println!("   • READ = BLOCK ALL rule enforced");
    println!("   • Kernel events forwarded to WebSocket");
    println!("   • Real-time blocking active");

     // Demonstrate STEP 6 functionality
    demonstrate_step6_kernel_enforcement();

    println!("\n⏳ Waiting for Admin connections...");
    println!("Press Ctrl+C to gracefully shutdown.\n");

    println!("\n==================================================");
    println!("🚀 ENTERPRISE DLP AGENT READY!");
    println!("==================================================");
    println!("📊 STATUS SUMMARY:");
    println!("   1. ✅ Filesystem Index (ID-based)");
    println!("   2. ✅ Communication Layer (ID-only protocol)");
    println!("   3. ✅ Explorer UI Behavior Logic");
    println!("   4. ✅ Policy Engine (Kernel bridge)");
    println!("   5. ✅ HTTP Server (Spring Boot API)");
    println!("   6. ✅ Security Boundary (No NT path exposure)");
    println!("==================================================");

    println!("\n🔗 SPRING BOOT ADMIN CAN CONNECT:");
    println!("   HTTP Endpoint: http://{}", bind_address);
    println!("   API Base: /api/v1");
    println!("\n📡 AVAILABLE ENDPOINTS:");
    println!("   GET  /api/v1/drives            - List all drives");
    println!("   GET  /api/v1/nodes/:id         - Get node info");
    println!("   GET  /api/v1/nodes/:id/children - List children");
    println!("   POST /api/v1/nodes/:id/expand  - Expand directory");
    println!("   POST /api/v1/nodes/:id/collapse - Collapse directory");
    println!("   GET  /api/v1/search/local      - Local search");
    println!("   GET  /api/v1/stats             - System stats");
    println!("   POST /api/v1/policies/apply    - Apply protection");
    println!("   DELETE /api/v1/policies/:id    - Remove protection");
    println!("   GET  /api/v1/policies          - List all policies");
    println!("   GET  /api/v1/ping              - Health check");
    println!("==================================================");

    println!("\n🔒 SECURITY MODEL ENFORCED:");
    println!("   • Admin only sees node IDs");
    println!("   • NT paths never leave the Agent");
    println!("   • Kernel rules enforced locally");
    println!("   • Policy validation at every step");
    println!("==================================================");

    println!("\n⏳ Waiting for Admin Server connections...");
    println!("Press Ctrl+C to gracefully shutdown.\n");

    // Wait forever (server runs in background)
    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
    println!("\n🛑 Agent shutting down gracefully...");

    // Stop kernel event bridge
    bridge_handle.abort();
    println!("✅ Kernel event bridge stopped");
    
    // Gracefully shutdown networking
    if let Some(handle) = server_handle {
        handle.shutdown().await?;
        println!("✅ Networking layer shut down");
    }

     println!("✅ Agent shutdown complete");
    Ok(())
}

/// Demonstrate STEP 6 functionality
fn demonstrate_step6_kernel_enforcement() {
    println!("\n🔧 STEP 6 DEMONSTRATION:");
    println!("   Showing Kernel Enforcement & READ = BLOCK ALL rule");
    
    println!("\n📋 CRITICAL ENTERPRISE RULES:");
    println!("   1. READ = BLOCK ALL");
    println!("      • If read is blocked, ALL operations are blocked");
    println!("      • This prevents copy, execute, preview, metadata access");
    println!("      • Enterprise DLP standard behavior");
    
    println!("\n📋 EXAMPLE SCENARIOS:");
    println!("   Scenario 1: Read-only file protection");
    println!("      • Admin blocks READ on confidential.docx");
    println!("      • User tries to open → BLOCKED");
    println!("      • User tries to copy → BLOCKED (READ = BLOCK ALL)");
    println!("      • User tries to delete → BLOCKED (READ = BLOCK ALL)");
    
    println!("\n   Scenario 2: Write-only protection");
    println!("      • Admin blocks WRITE only (READ = false)");
    println!("      • User can read, copy, execute the file");
    println!("      • User cannot modify, delete, or rename");
    
    println!("\n📋 REAL-TIME EVENTS:");
    println!("   1. Kernel intercepts filesystem operation");
    println!("   2. Checks policy matching (node_id → NT path)");
    println!("   3. Applies READ = BLOCK ALL rule");
    println!("   4. Sends event to Agent (kernel_event_bridge)");
    println!("   5. Agent forwards to WebSocket");
    println!("   6. Admin UI shows real-time alert");
    
    println!("\n💡 SECURITY BOUNDARIES MAINTAINED:");
    println!("   • Kernel never sees node IDs");
    println!("   • Agent resolves IDs → NT paths internally");
    println!("   • WebSocket events contain IDs only");
    println!("   • Admin never sees NT paths");
}
async fn demonstrate_step3_ui_behavior(explorer: &ui::ExplorerController) {
    println!("\n🔍 STEP 3 DEMONSTRATION (Local Testing):");
    println!("   Showing Explorer UI behavior using STEP 2 APIs");
    
    // Initialize explorer (load drives)
    match explorer.initialize().await {
        Ok(drive_ids) => {
            println!("   ✅ Explorer initialized with {} drives", drive_ids.len());
            
            if !drive_ids.is_empty() {
                let first_drive_id = drive_ids[0];
                
                // Demonstrate folder click (selects, doesn't expand)
                println!("   📝 Example: Folder Click (Selects, doesn't expand)");
                explorer.interaction_engine().handle_drive_click(
                    first_drive_id,
                    "Local Disk",
                    "C:",
                    true
                ).await;
                
                // Demonstrate "Mark for Protection"
                println!("   📝 Example: Mark for Protection (STEP 4 preparation)");
                explorer.interaction_engine().handle_mark_for_protection(
                    first_drive_id,
                    "drive",
                    "Local Disk (C:)",
                    None,
                    1700000000,
                ).await.unwrap_or_else(|e| {
                    println!("   ⚠️ Mark for protection failed: {}", e);
                });
            }
        }
        Err(e) => println!("   ❌ Failed to initialize explorer: {}", e),
    }
    
    println!("\n💡 KEY STEP 3 PRINCIPLES DEMONSTRATED:");
    println!("   1. UI maintains its own state (expand/collapse/selection)");
    println!("   2. All interactions use STEP 2 APIs (IDs only)");
    println!("   3. 'Mark for Protection' stores selection for STEP 4");
    println!("   4. No NT paths exposed to Admin");
    println!("   5. No kernel calls (pure UI behavior)");
}

/// Demonstrate STEP 3 UI behavior with error handling
async fn demonstrate_step3_ui_behavior_with_errors(explorer: &ui::ExplorerController) {
    println!("\n🔍 STEP 3 DEMONSTRATION (with Expand/Collapse):");
    
    // Initialize explorer
    let drive_ids = match explorer.initialize().await {
        Ok(ids) => {
            println!("   ✅ Loaded {} drives", ids.len());
            ids
        }
        Err(e) => {
            println!("   ❌ Failed to load drives: {}", e);
            return;
        }
    };
    
    if drive_ids.is_empty() {
        println!("   ⚠️ No drives found");
        return;
    }
    
    let first_drive_id = drive_ids[0];
    
    // 1. Select a drive
    println!("\n   1. Selecting drive...");
    explorer.interaction_engine().handle_drive_click(
        first_drive_id,
        "Local Disk",
        "C:",
        true
    ).await;
    
    // 2. Try to expand
    println!("\n   2. Trying to expand drive...");
    match explorer.interaction_engine().handle_expand_click(first_drive_id, "Local Disk (C:)").await {
        Ok(_) => println!("   ✅ Expansion successful"),
        Err(e) => println!("   ❌ Expansion failed: {}", e),
    }
    
    // 3. Load children after expansion
    println!("\n   3. Loading children...");
    match explorer.load_children(first_drive_id).await {
        Ok(children) => println!("   ✅ Loaded {} children", children.len()),
        Err(e) => println!("   ❌ Failed to load children: {}", e),
    }
    
    // 4. Try to expand again (should fail with AlreadyExpanded)
    println!("\n   4. Trying to expand again (should fail)...");
    match explorer.interaction_engine().handle_expand_click(first_drive_id, "Local Disk (C:)").await {
        Ok(_) => println!("   ⚠️ Unexpectedly succeeded"),
        Err(e) => println!("   ✅ Expected error: {}", e),
    }
    
    // 5. Search demonstration
    println!("\n   5. Searching within expanded nodes...");
    match explorer.interaction_engine().handle_search(first_drive_id, "*.txt", None).await {
        Ok(result_ids) => println!("   ✅ Search found {} results", result_ids.len()),
        Err(e) => println!("   ❌ Search failed: {}", e),
    }
    
    // 6. Collapse demonstration
    println!("\n   6. Collapsing drive...");
    match explorer.interaction_engine().handle_collapse_click(first_drive_id, "Local Disk (C:)").await {
        Ok(_) => println!("   ✅ Collapse successful"),
        Err(e) => println!("   ❌ Collapse failed: {}", e),
    }
    
    // Show summary
    println!("\n📊 Final UI State:");
    explorer.show_summary();
}


// pub mod fltlib;
// use fltlib::*;
// use windows_sys::Win32::Foundation::*;
// use std::ptr;
// use std::collections::HashMap;
// use std::sync::Mutex;
// use once_cell::sync::Lazy;
// // use ctrlc;

// fn wide(s: &str) -> Vec<u16> {
//     s.encode_utf16().chain(Some(0)).collect()
// }

// // Global policy registry
// type PolicyKey = String; // Normalized NT path (folders end with \)
// static ACTIVE_POLICIES: Lazy<Mutex<HashMap<PolicyKey, FilePolicy>>> = Lazy::new(|| {
//     Mutex::new(HashMap::new())
// });

// #[repr(C)]
// #[derive(Clone, Copy)]
// struct FilePolicy {
//     pub path: [u16; 260],
//     pub is_folder: u8,
//     pub block_read: u8,
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_all: u8,
//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

// /// Normalize NT path consistently
// /// - Converts to UTF-16
// /// - For folders: ensures trailing backslash
// /// - Truncates to 259 characters (leaving room for optional trailing backslash)
// fn normalize_nt_path(path: &str, is_folder: bool) -> (Vec<u16>, String) {
//     let mut normalized = String::from(path);

//     // Trim and normalize
//     normalized = normalized.trim().replace('/', "\\");

//     // Ensure proper NT path format
//     if !normalized.starts_with("\\Device\\") {
//         // If not already an NT path, assume it's already normalized from user input
//         // (In production, you'd want to validate this more thoroughly)
//     }

//     // For folders, ensure trailing backslash
//     if is_folder && !normalized.ends_with('\\') {
//         normalized.push('\\');
//     }

//     // Convert to UTF-16
//     let wide_str: Vec<u16> = normalized.encode_utf16().collect();

//     (wide_str, normalized)
// }

// fn make_policy(
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> (FilePolicy, String) {
//     let (wide_str, normalized_path) = normalize_nt_path(path, is_folder);

//     let mut p = FilePolicy {
//         path: [0; 260],
//         is_folder: if is_folder { 1 } else { 0 },
//         block_read,
//         block_write,
//         block_delete,
//         block_rename,
//         block_create,
//         block_all,
//         timestamp: std::time::SystemTime::now()
//             .duration_since(std::time::UNIX_EPOCH)
//             .unwrap()
//             .as_secs(),
//         added_by: [0; 64],
//         reserved: [0; 8],
//     };

//     // Copy the normalized path
//     let copy_len = wide_str.len().min(259);
//     p.path[..copy_len].copy_from_slice(&wide_str[..copy_len]);

//     (p, normalized_path)
// }

// /// Remove a policy by sending zeroed flags
// fn remove_policy_internal(handle: HANDLE, path: &str, is_folder: bool) -> bool {
//     let (remove_policy, normalized_path) = make_policy(path, is_folder, 0, 0, 0, 0, 0, 0);
//     send_policy(handle, &remove_policy, &format!("Remove policy: {}", normalized_path))
// }

// /// Apply a policy with proper update logic
// fn apply_policy(
//     handle: HANDLE,
//     path: &str,
//     is_folder: bool,
//     block_read: u8,
//     block_write: u8,
//     block_delete: u8,
//     block_rename: u8,
//     block_create: u8,
//     block_all: u8
// ) -> bool {
//     let (new_policy, normalized_path) = make_policy(
//         path, is_folder,
//         block_read, block_write, block_delete,
//         block_rename, block_create, block_all
//     );

//     // Check if policy already exists
//     let mut policies = ACTIVE_POLICIES.lock().unwrap();

//     if let Some(existing_policy) = policies.get(&normalized_path) {
//         // Policy exists - remove it first
//         println!("⚠️ Policy exists for {}, removing old policy...", normalized_path);

//         let (remove_policy, _) = make_policy(path, is_folder, 0, 0, 0, 0, 0, 0);
//         if !send_policy(handle, &remove_policy, &format!("Remove old policy: {}", normalized_path)) {
//             println!("❌ Failed to remove old policy");
//             return false;
//         }
//     }

//     // Send new policy
//     let description = if policies.contains_key(&normalized_path) {
//         format!("Update policy: {}", normalized_path)
//     } else {
//         format!("Add policy: {}", normalized_path)
//     };

//     if send_policy(handle, &new_policy, &description) {
//         // Store in registry
//         policies.insert(normalized_path.clone(), new_policy);
//         true
//     } else {
//         false
//     }
// }

// /// Remove a policy from both kernel and registry
// fn remove_policy(handle: HANDLE, path: &str, is_folder: bool) -> bool {
//     let (_, normalized_path) = normalize_nt_path(path, is_folder);
//     let mut policies = ACTIVE_POLICIES.lock().unwrap();

//     if policies.contains_key(&normalized_path) {
//         if remove_policy_internal(handle, path, is_folder) {
//             policies.remove(&normalized_path);
//             println!("✅ Removed policy for: {}", normalized_path);
//             true
//         } else {
//             println!("❌ Failed to remove policy for: {}", normalized_path);
//             false
//         }
//     } else {
//         println!("⚠️ No active policy found for: {}", normalized_path);
//         false
//     }
// }

// /// Cleanup all policies on exit
// fn cleanup_all_policies(handle: HANDLE) {
//     println!("🧹 Cleaning up all active policies...");

//     let mut policies = ACTIVE_POLICIES.lock().unwrap();
//     let count = policies.len();

//     if count == 0 {
//         println!("✅ No active policies to clean up");
//         return;
//     }

//     println!("📋 Removing {} active policies...", count);

//     let mut successful = 0;
//     let mut failed = 0;

//     // Create a copy of keys to avoid borrowing issues
//     let keys: Vec<(String, bool)> = policies.iter()
//         .map(|(path, policy)| (path.clone(), policy.is_folder == 1))
//         .collect();

//     for (path, is_folder) in keys {
//         if remove_policy_internal(handle, &path, is_folder) {
//             successful += 1;
//         } else {
//             failed += 1;
//         }
//     }

//     // Clear the registry
//     policies.clear();

//     println!("✅ Cleanup complete:");
//     println!("   Successful removals: {}", successful);
//     println!("   Failed removals: {}", failed);

//     if failed > 0 {
//         println!("⚠️ WARNING: Some policies may still be active in kernel!");
//     }
// }

// fn send_policy(handle: HANDLE, policy: &FilePolicy, description: &str) -> bool {
//     let mut returned: u32 = 0;
//     let status = unsafe {
//         FilterSendMessage(
//             handle,
//             policy as *const _ as _,
//             std::mem::size_of::<FilePolicy>() as u32,
//             ptr::null_mut(),
//             0,
//             &mut returned,
//         )
//     };

//     if status == 0 {
//         println!("✅ {}", description);
//         true
//     } else {
//         println!("❌ Failed to send {}: NTSTATUS=0x{:X}", description, status);
//         false
//     }
// }

// /// Display current active policies
// fn list_policies() {
//     let policies = ACTIVE_POLICIES.lock().unwrap();

//     println!("📋 Active Policies ({}):", policies.len());
//     println!("{:-<80}", "");

//     for (path, policy) in policies.iter() {
//         let policy_type = if policy.is_folder == 1 { "Folder" } else { "File " };
//         println!("{}: {}", policy_type, path);
//         println!("  Flags: R{} W{} D{} RN{} C{} A{}",
//             policy.block_read,
//             policy.block_write,
//             policy.block_delete,
//             policy.block_rename,
//             policy.block_create,
//             policy.block_all
//         );
//         println!();
//     }
// }

// fn main() {
//     println!("DLP PHASE-1 - NT PATHS ONLY");
//     println!("============================\n");

//     println!("Connecting to kernel driver...");

//     let mut handle: HANDLE = 0;
//     let port = wide("\\DlpPort");

//     let status = unsafe {
//         FilterConnectCommunicationPort(
//             port.as_ptr(),
//             0,
//             ptr::null(),
//             0,
//             ptr::null_mut(),
//             &mut handle,
//         )
//     };

//     if status != 0 {
//         println!("❌ Failed to connect to kernel: NTSTATUS=0x{:X}", status);
//         return;
//     }

//     println!("✅ Connected to kernel driver!\n");

//     // Setup Ctrl+C handler for cleanup
//     let handle_for_ctrlc = handle;
//     ctrlc::set_handler(move || {
//         println!("\n🛑 Ctrl+C received, cleaning up...");
//         cleanup_all_policies(handle_for_ctrlc);
//         std::process::exit(0);
//     }).expect("Error setting Ctrl+C handler");

//     println!("IMPORTANT: Using NT paths only\n");
//     println!("Example NT paths (use DebugView to see real paths):");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\TopSecret\\\\");
//     println!("• \\\\Device\\\\HarddiskVolume4\\\\Users\\\\Test\\\\file.txt");
//     println!();

//     // TEST: Apply some initial policies
//     println!("1. Setting immutability for NT folder:");
//     apply_policy(
//         handle,
//         "\\Device\\HarddiskVolume4\\Agentstarts",
//         true,    // folder
//         0,       // block_read = 0 (ALLOW reading)
//         1,       // block_write = 1 (BLOCK modifications)
//         1,       // block_delete = 1 (BLOCK deletion)
//         1,       // block_rename = 1 (BLOCK rename)
//         1,       // block_create = 1 (BLOCK new files)
//         0        // block_all = 0
//     );

//     println!("\n2. Protecting specific file: ");
//     apply_policy(
//         handle,
//         "\\Device\\HarddiskVolume4\\TopSecret\\Saurabh_Gupta_Resum.pdf",
//         false,   // file
//         0,       // block_read = 0
//         0,       // block_write = 1
//         0,       // block_delete = 1
//         0,       // block_rename = 1
//         0,       // block_create = 0 (N/A for files)
//         1        // block_all = 0
//     );

//        false,   // file
//         0,       // block_read = 0 ye hmesha 0 rhega kyuki ye work nhi krta hai isliye 
//         0,       // block_write = 0
//         0,       // block_delete = 0
//         0,       // block_rename = 0
//         0,       // block_create = 0 (N/A for files)
//         1        // block_all = 1 abhi maine blaock_all ko 1 kiya hai to isme sab blaock hoga including the read bhi alag se kuchh kren ki jrurat nhi hai 

//     println!("\n============================");
//     println!("PHASE-1 ACTIVE");
//     println!("============================");
//     println!("Will BLOCK:");
//     println!("  • Write/modify");
//     println!("  • Delete");
//     println!("  • Rename");
//     println!("  • Create new files");
//     println!("  • Memory-mapped writes (PDF/Office)");
//     println!("\nWill ALLOW:");
//     println!("  • Read/open/view");
//     println!("  • Directory listing");
//     println!("============================\n");

//     println!("Commands:");
//     println!("  test        - Send test paths");
//     println!("  list        - Show active policies");
//     println!("  apply       - Apply new policy (interactive)");
//     println!("  update      - Update existing policy (interactive)");
//     println!("  remove <path> - Remove policy for path");
//     println!("  cleanup     - Remove all policies");
//     println!("  exit        - Quit and cleanup");

//     loop {
//         print!("> ");
//         std::io::Write::flush(&mut std::io::stdout()).unwrap();

//         let mut input = String::new();
//         std::io::stdin().read_line(&mut input).unwrap();
//         let input = input.trim();
//         let lower_input = input.to_lowercase();

//         match lower_input.as_str() {
//             "exit" => {
//                 println!("Exiting...");
//                 cleanup_all_policies(handle);
//                 break;
//             },
//             "test" => {
//                 println!("Test: Applying sample policy...");
//                 apply_policy(
//                     handle,
//                     "\\Device\\HarddiskVolume4\\TestFolder",
//                     true,
//                     0, 1, 1, 1, 1, 0
//                 );
//             },
//             "list" => {
//                 list_policies();
//             },
//             "apply" | "update" => {
//                 println!("Enter NT path:");
//                 let mut path = String::new();
//                 std::io::stdin().read_line(&mut path).unwrap();
//                 let path = path.trim();

//                 println!("Is folder? (y/n):");
//                 let mut is_folder = String::new();
//                 std::io::stdin().read_line(&mut is_folder).unwrap();
//                 let is_folder = is_folder.trim().to_lowercase() == "y";

//                 println!("Block read? (0/1):");
//                 let mut block_read = String::new();
//                 std::io::stdin().read_line(&mut block_read).unwrap();
//                 let block_read = block_read.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block write? (0/1):");
//                 let mut block_write = String::new();
//                 std::io::stdin().read_line(&mut block_write).unwrap();
//                 let block_write = block_write.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block delete? (0/1):");
//                 let mut block_delete = String::new();
//                 std::io::stdin().read_line(&mut block_delete).unwrap();
//                 let block_delete = block_delete.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block rename? (0/1):");
//                 let mut block_rename = String::new();
//                 std::io::stdin().read_line(&mut block_rename).unwrap();
//                 let block_rename = block_rename.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block create? (0/1):");
//                 let mut block_create = String::new();
//                 std::io::stdin().read_line(&mut block_create).unwrap();
//                 let block_create = block_create.trim().parse::<u8>().unwrap_or(0);

//                 println!("Block all? (0/1):");
//                 let mut block_all = String::new();
//                 std::io::stdin().read_line(&mut block_all).unwrap();
//                 let block_all = block_all.trim().parse::<u8>().unwrap_or(0);

//                 apply_policy(
//                     handle,
//                     path,
//                     is_folder,
//                     block_read,
//                     block_write,
//                     block_delete,
//                     block_rename,
//                     block_create,
//                     block_all
//                 );
//             },
//             cmd if cmd.starts_with("remove ") => {
//                 let path = &cmd[7..].trim();
//                 println!("Removing policy for: {}", path);

//                 println!("Is folder? (y/n):");
//                 let mut is_folder = String::new();
//                 std::io::stdin().read_line(&mut is_folder).unwrap();
//                 let is_folder = is_folder.trim().to_lowercase() == "y";

//                 remove_policy(handle, path, is_folder);
//             },
//             "cleanup" => {
//                 cleanup_all_policies(handle);
//             },
//             _ => {
//                 println!("Available commands:");
//                 println!("  test        - Send test paths");
//                 println!("  list        - Show active policies");
//                 println!("  apply       - Apply new policy");
//                 println!("  update      - Update existing policy");
//                 println!("  remove <path> - Remove policy for path");
//                 println!("  cleanup     - Remove all policies");
//                 println!("  exit        - Quit and cleanup");
//             },
//         }
//     }

//     println!("DLP Agent terminated.");
// }
