#![no_std] // No standard library in the kernel
#![cfg_attr(not(test), no_main)]

use core::ffi::c_void;
use fsfilter::filter_callbacks;
use fsfilter::kernel::filter::{Filter, FilterCallbacks, OperationType};
use fsfilter::kernel::message::{CommunicationPort, Message, ReplyMessage};
use fsfilter::kernel::traits::FromIrp;
use fsfilter::kernel::types::{FLT_CALLBACK_DATA, FLT_INSTANCE, FLT_PREOP_CALLBACK_STATUS};
use fsfilter::flt_status;

use windows_sys::Win32::Foundation::{STATUS_ACCESS_DENIED, STATUS_SUCCESS};
use windows_sys::Win32::Storage::FileSystem::{
    IRP_MJ_CREATE, IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION,
};

// --- These MUST match the structs in the "Brain" ---
#[repr(C)]
#[derive(Debug)]
struct KernelMessage {
    operation: u32,
    process_id: u32,
    file_path: [u16; 260], // Windows MAX_PATH
}

#[repr(C)]
#[derive(Debug)]
struct UserReply {
    should_allow: bool, // "Brain" replies with an "allow" decision
}
// ---

// Define our filter, holding the communication port
struct DlpFilter {
    port: CommunicationPort,
}

impl DlpFilter {
    /// This is our "OS Allow-List" to prevent system crashes.
    fn is_trusted_system_process(process_id: u32, file_path: &fsfilter::kernel::file_name::FileName) -> bool {
        // Process ID 4 is the "System" process. It MUST be allowed.
        if process_id == 4 {
            return true;
        }

        let path_slice = file_path.name().as_slice();
        
        // Allow-list for critical Windows folders.
        // We check for `\Windows\` (case-insensitive)
        let windows_path: [u16; 9] = [92, 87, 105, 110, 100, 111, 119, 115, 92]; // \Windows\
        if path_slice.len() > 9 && path_slice[1..10].eq_ignore_ascii_case(&windows_path) {
            return true;
        }
        
        // This is a minimal list. A production product would also whitelist
        // svchost.exe, lsass.exe, services.exe, etc.
        
        false
    }
}

impl FilterCallbacks for DlpFilter {
    /// This is the "Gate". It's called BEFORE every file operation.
    fn pre_operation_callback(
        &mut self,
        callback_data: &mut FLT_CALLBACK_DATA,
        _instance: &FLT_INSTANCE,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        
        let operation = callback_data.Iopb.MajorFunction;

        // We intercept all major file operations
        let is_relevant_op = matches!(operation, 
            IRP_MJ_CREATE | // File Open, Create, Rename
            IRP_MJ_READ   | // File Read
            IRP_MJ_WRITE  | // File Write
            IRP_MJ_SET_INFORMATION // File Delete, Rename
        );

        if !is_relevant_op {
            return flt_status::FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // Get file name and process ID
        let (file_name, process_id) = unsafe {
            (
                fsfilter::kernel::file_name::get_file_name_information(callback_data),
                fsfilter::kernel::operations::get_requestor_process_id(callback_data)
            )
        };

        if let Ok(file_name) = file_name {
            if file_name.name().is_empty() {
                return flt_status::FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            // 1. "Default-Allow for OS"
            if Self::is_trusted_system_process(process_id, &file_name) {
                return flt_status::FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            // 2. "Default-Deny for Users": Ask the "Brain"
            let mut message = KernelMessage {
                operation,
                process_id,
                file_path: [0; 260],
            };
            let path_slice = file_name.name().as_slice();
            let len = core::cmp::min(path_slice.len(), message.file_path.len() - 1);
            message.file_path[..len].copy_from_slice(&path_slice[..len]);

            let mut reply = UserReply { should_allow: false }; // Default to DENY
            let result = self.port.send_message_timeout(
                &Message::new(&message),
                Some(&mut ReplyMessage::new(&mut reply)),
                core::time::Duration::from_millis(1000), // 1 second timeout
            );

            // 3. Make a decision based on the reply
            match result {
                Ok(status) if status == STATUS_SUCCESS => {
                    if reply.should_allow {
                        // The Brain explicitly ALLOWED this.
                        return flt_status::FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                }
                Err(status) => {
                    // Error communicating (agent not running?). Enforce "Default-Deny".
                    log::error!("Failed to send message to user-mode: {}. Blocking.", status);
                }
                _ => {
                    // Timeout or other error. Enforce "Default-Deny".
                }
            }
        }

        // 4. Default Action: BLOCK
        // If we reach this point, it's a user operation that wasn't explicitly allowed.
        callback_data.IoStatus.Status = STATUS_ACCESS_DENIED;
        return flt_status::FLT_PREOP_COMPLETE;
    }

    fn client_connect(&mut self, _client_port: windows_sys::Win32::Foundation::HANDLE, _connection_cookie: *mut c_void) -> i32 {
        log::info!("User-mode agent connected.");
        STATUS_SUCCESS
    }

    fn client_disconnect(&mut self, _connection_cookie: *mut c_void) {
        log::info!("User-mode agent disconnected.");
    }
}

// 5. Register our filter with Windows
filter_callbacks! {
    DlpFilter,
    // This is the port name our agent will use to connect
    port_name: "DlpFileFilterPort",
    // This defines the UUID for our driver.
    // You can generate a new one online at "Online UUID Generator"
    filter_uuid: "12345678-ABCD-EF01-2345-6789ABCDEF01",
}