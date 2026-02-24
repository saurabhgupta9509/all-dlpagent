//! Kernel Adapter (STEP 4.4)
//! Core Principle: Convert kernel policy to binary messages for minifilter
// src/policy/kernel_adapter.rs
use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::HANDLE;
use std::ptr;
use crate::protection_modules::file_protection::{fltlib, kernel::KernelEvent, policy::PathMatchType};

use super::kernel_policy::{KernelPolicy, KernelOperations};
/// Kernel policy message (must match minifilter structure)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
// pub struct KernelPolicyMessage {
//     pub policy_id: u64,
//     pub path: [u16; 260],           // NT path in UTF-16
//     pub match_type: u8,             // 0 = exact, 1 = prefix
//     pub is_recursive: u8,           // 0 = no, 1 = yes
//      pub block_read: u8,      // always 0 (READ expanded)
//     pub block_write: u8,
//     pub block_delete: u8,
//     pub block_rename: u8,
//     pub block_create: u8,
//     pub block_copy: u8,      // ✅ ADD THIS
//     pub block_execute: u8,   

//     pub audit_read: u8,      // always 0 (READ expanded)
//     pub audit_write: u8,
//     pub audit_delete: u8,
//     pub audit_rename: u8,
//     pub audit_create: u8,
//     pub audit_copy: u8,      // ✅ ADD THIS
//     pub audit_execute: u8,

//     pub timestamp: u64,
//     pub added_by: [u16; 64],
//     pub reserved: [u8; 8],
// }

pub struct FilePolicy {
    pub path: [u16; 260],
    pub is_folder: u8,
    pub block_read: u8,
    pub block_write: u8,
    pub block_delete: u8,
    pub block_rename: u8,
    pub block_create: u8,
    pub block_all: u8,
    pub timestamp: u64,
    pub added_by: [u16; 64],
    pub reserved: [u8; 8],
}

impl FilePolicy  {
    /// Create from 
    // pub fn from_kernel_policy(policy: &KernelPolicy) -> Self {
    //     // Convert NT path to UTF-16
    //     let mut path_wide = [0u16; 260];
    //     let wide_chars: Vec<u16> = policy.nt_path.encode_utf16().collect();
    //     let copy_len = wide_chars.len().min(259);
    //     path_wide[..copy_len].copy_from_slice(&wide_chars[..copy_len]);
        
    //     // Convert added_by to UTF-16
    //     let mut added_by_wide = [0u16; 64];
    //     let added_by_chars: Vec<u16> = policy.created_by.encode_utf16().collect();
    //     let added_by_len = added_by_chars.len().min(63);
    //     added_by_wide[..added_by_len].copy_from_slice(&added_by_chars[..added_by_len]);
        
    //     // Get operation flags
    //     let (b_write, b_delete, b_rename, b_create, b_copy , b_execute) = policy.blocked_ops.to_flags();
    //     // let (a_read, a_write, a_delete, a_rename, a_create, b_copy , b_execute) = policy.audit_ops.to_flags();
        
    //     KernelPolicyMessage {
    //         path: path_wide,
    //         is_folder = policy.match_type == Prefix,
    //         block_read: 0,
    //         block_write: b_write,
    //         block_delete: b_delete,
    //         block_rename: b_rename,
    //         block_create: b_create,

    //         timestamp: policy.timestamp,
    //         added_by: added_by_wide,
    //         reserved: [0; 8],
    //     }
    // }


// pub fn from_kernel_policy(policy: &KernelPolicy) -> Self {
//     // -----------------------------
//     // NT path → UTF-16 (MAX 259)
//     // -----------------------------
//     let mut path_wide = [0u16; 260];
//     let wide_chars: Vec<u16> = policy.nt_path.encode_utf16().collect();
//     let copy_len = wide_chars.len().min(259);
//     path_wide[..copy_len].copy_from_slice(&wide_chars[..copy_len]);

//     // -----------------------------
//     // added_by → UTF-16 (MAX 63)
//     // -----------------------------
//     let mut added_by_wide = [0u16; 64];
//     let added_by_chars: Vec<u16> = policy.created_by.encode_utf16().collect();
//     let added_by_len = added_by_chars.len().min(63);
//     added_by_wide[..added_by_len].copy_from_slice(&added_by_chars[..added_by_len]);

//     // -----------------------------
//     // Operation flags
//     // -----------------------------
//     // let (b_read ,b_write, b_delete, b_rename, b_create, _b_copy, _b_execute) =
//     //     policy.blocked_ops.to_flags();
//       let (b_read, b_write, b_delete, b_rename, b_create , b_copy ,b_execute) = 
//         policy.blocked_ops.to_flags();

//          // OLD KERNEL: is_folder = 1 for folders
//         let is_folder = match policy.match_type {
//             PathMatchType::Prefix => 1,
//             PathMatchType::Exact => 0,
//         };
    
    
//     // READ = BLOCK ALL rule (enterprise DLP)
//    let block_all: u8 = if policy.blocked_ops.is_block_all() { 1 } else { 0 };

//     // -----------------------------
//     // FINAL KERNEL MESSAGE
//     // -----------------------------
//     FilePolicy  {
//         path: path_wide,
//         is_folder,
//         block_read: b_read, // kernel never blocks read directly
//         block_write: b_write,
//         block_delete: b_delete,
//         block_rename: b_rename,
//         block_create: b_create,
//         block_all:0,
//         timestamp: policy.timestamp,
//         added_by: added_by_wide,
//         reserved: [0; 8],
//     }
// }


pub fn from_kernel_policy(policy: &KernelPolicy) -> Self {

     println!("🔧 DEBUG: Creating FilePolicy from KernelPolicy:");
     println!("  NT Path: {}", policy.nt_path);
     println!("  Block All: {}", policy.block_all);

    // -----------------------------
    // NT path → UTF-16 (MAX 259)
    // -----------------------------
    let mut path_wide = [0u16; 260];
    let wide_chars: Vec<u16> = policy.nt_path.encode_utf16().collect();
    let copy_len = wide_chars.len().min(259);
    path_wide[..copy_len].copy_from_slice(&wide_chars[..copy_len]);

    // -----------------------------
    // added_by → UTF-16 (MAX 63)
    // -----------------------------
    let mut added_by_wide = [0u16; 64];
    let added_by_chars: Vec<u16> = policy.created_by.encode_utf16().collect();
    let added_by_len = added_by_chars.len().min(63);
    added_by_wide[..added_by_len].copy_from_slice(&added_by_chars[..added_by_len]);

    // -----------------------------
    // Operation flags
    // -----------------------------
    // Old kernel logic: block_read हमेशा 0
    let ( b_write, b_delete, b_rename, b_create) = 
        policy.blocked_ops.to_flags();
    
    // OLD KERNEL: is_folder = 1 for folders
    let is_folder = match policy.match_type {
        PathMatchType::Prefix => 1,
        PathMatchType::Exact => 0,
    };
    
    // READ = BLOCK ALL rule (enterprise DLP)
    let block_all: u8 = if policy.block_all { 1 } else { 0 };

       println!("🔧 DEBUG FilePolicy creation:");
    println!("   Path: {}", policy.nt_path);
    println!("   is_block_all() = {}", policy.block_all);
    println!("   block_all = {}", block_all);
    println!("   Operations: W{} D{} RN{} C{}",
        b_write, b_delete, b_rename, b_create);

        
    // -----------------------------
    // FINAL KERNEL MESSAGE - FIXED!
    // -----------------------------
    FilePolicy {
        path: path_wide,
        is_folder,
        block_read: 0,       // Old kernel में ये काम नहीं करता
        block_write: b_write,
        block_delete: b_delete,
        block_rename: b_rename,
        block_create: b_create,
        block_all, // <-- यहाँ variable use करो!
        timestamp: policy.timestamp,
        added_by: added_by_wide,
        reserved: [0; 8],
    }
}

}

/// Kernel adapter - communicates with minifilter
pub struct KernelAdapter {
    kernel_handle: HANDLE,
    next_policy_id: u64,
    event_sender: Option<mpsc::Sender<KernelEvent>>, // For STEP 6.3
}

impl KernelAdapter {
    /// Create new kernel adapter
    pub fn new(event_sender: Option<mpsc::Sender<KernelEvent>>) -> Result<Self, String> {
        println!("🔌 KernelAdapter: Connecting to minifilter...");
        
        let mut handle: HANDLE = 0;
        let port_name = "\\DlpPort";
        
        // Convert to wide string
        let wide_port: Vec<u16> = port_name.encode_utf16().chain(Some(0)).collect();
        
        let status = unsafe {
            fltlib::FilterConnectCommunicationPort(
                wide_port.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut handle,
            )
        };
        
        if status != 0 {
            let error = format!("Failed to connect to kernel: NTSTATUS=0x{:X}", status);
            println!("❌ {}", error);
            return Err(error);
        }
        
        println!("✅ KernelAdapter: Connected to minifilter");
        Ok(KernelAdapter {
            kernel_handle: handle,
            next_policy_id: 1, // Start from 1
            event_sender,
        })
    }
      /// Set kernel event sender (can be called after initialization)
      pub fn set_event_sender(&mut self, event_sender: tokio::sync::mpsc::Sender<KernelEvent>) {
        self.event_sender = Some(event_sender);
        println!("🔌 KernelAdapter: Event sender attached");
    }

    /// Send policy to kernel
    pub fn send_policy(&mut self, policy: &KernelPolicy) -> Result<u64, String> {
        println!("📤 KernelAdapter: Sending policy to kernel (ID: {})", policy.policy_id);
        println!("   Path: {}", policy.nt_path);
        
        // Create kernel message
        let message = FilePolicy ::from_kernel_policy(policy);
        
        // Send to kernel
        let mut bytes_returned: u32 = 0;
        let status = unsafe {
            fltlib::FilterSendMessage(
                self.kernel_handle,
                &message as *const _ as _,
                std::mem::size_of::<FilePolicy >() as u32,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
            )
        };
        
        if status == 0 {
            println!("✅ KernelAdapter: Policy sent successfully (ID: {})", policy.policy_id);
            Ok(policy.policy_id)
        } else {
            let error = format!("Failed to send policy to kernel: NTSTATUS=0x{:X}", status);
            println!("❌ {}", error);
            Err(error)
        }
    }
    
    /// Remove policy from kernel
   /// Remove policy from kernel
pub fn remove_policy(&mut self, policy_id: u64, nt_path: &str) -> Result<(), String> {
    println!("🗑️ KernelAdapter: Removing policy from kernel (ID: {})", policy_id);
    println!("   Path: {}", nt_path);

    // -----------------------------
    // NT path → UTF-16
    // -----------------------------
    let mut path_wide = [0u16; 260];
    let wide_chars: Vec<u16> = nt_path.encode_utf16().collect();
    let copy_len = wide_chars.len().min(259);
    path_wide[..copy_len].copy_from_slice(&wide_chars[..copy_len]);

    // -----------------------------
    // IMPORTANT:
    // Folder detection MUST match how it was added
    // (old driver used trailing backslash)
    // -----------------------------
    let is_folder: u8 = if nt_path.ends_with('\\') { 1 } else { 0 };

    // -----------------------------
    // ZEROED MESSAGE = REMOVE
    // -----------------------------
    let removal_message = FilePolicy  {
        path: path_wide,

        is_folder,

        block_read: 0,
        block_write: 0,
        block_delete: 0,
        block_rename: 0,
        block_create: 0,
        block_all: 0, // 🔥 CRITICAL (missing before)

        timestamp: 0,
        added_by: [0; 64],
        reserved: [0; 8],
    };

    // -----------------------------
    // Send to kernel
    // -----------------------------
    let mut bytes_returned: u32 = 0;
    let status = unsafe {
        fltlib::FilterSendMessage(
            self.kernel_handle,
            &removal_message as *const _ as _,
            std::mem::size_of::<FilePolicy >() as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
        )
    };

    if status == 0 {
        println!("✅ KernelAdapter: Policy removed successfully (ID: {})", policy_id);
        Ok(())
    } else {
        let error = format!("Failed to remove policy from kernel: NTSTATUS=0x{:X}", status);
        println!("❌ {}", error);
        Err(error)
    }
}

    
    /// Get next available policy ID
    pub fn get_next_policy_id(&mut self) -> u64 {
        let id = self.next_policy_id;
        self.next_policy_id += 1;
        id
    }
    
    /// Emit a kernel event (called by minifilter)
    pub fn emit_kernel_event(&self, event: KernelEvent) -> Result<(), String> {
        if let Some(sender) = &self.event_sender {
            // Try to send without blocking (use try_send)
            match sender.try_send(event) {
                Ok(_) => Ok(()),
                Err(e) => {
                    println!("⚠️ KernelAdapter: Failed to send event: {}", e);
                    Err(e.to_string())
                }
            }
        } else {
            // No event sender configured
            Ok(())
        }
    }
    
    /// Close kernel connection
    pub fn close(&self) {
        println!("🔌 KernelAdapter: Closing connection");
        // Note: In production, you might want to close the handle properly
    }
}