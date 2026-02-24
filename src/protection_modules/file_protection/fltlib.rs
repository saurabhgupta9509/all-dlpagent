// src/fitlib.rs
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::QueryDosDeviceW};
#[link(name = "fltlib")]
extern "system" {
    pub fn FilterConnectCommunicationPort(
        lpPortName: *const u16,
        dwOptions: u32,
        lpContext: *const core::ffi::c_void,
        dwSizeOfContext: u16,
        lpSecurityAttributes: *mut core::ffi::c_void,
        hPort: *mut HANDLE,
    ) -> NTSTATUS;

    pub fn FilterSendMessage(
        hPort: HANDLE,
        lpInBuffer: *const core::ffi::c_void,
        dwInBufferSize: u32,
        lpOutBuffer: *mut core::ffi::c_void,
        dwOutBufferSize: u32,
        lpBytesReturned: *mut u32,
    ) -> NTSTATUS;
}

pub fn query_dos_device(device_name: &str) -> Result<String, String> {
    let device_wide: Vec<u16> = device_name.encode_utf16().chain(Some(0)).collect();
    let mut target_path = vec![0u16; MAX_PATH as usize];
    
    unsafe {
        let result = QueryDosDeviceW(
            device_wide.as_ptr(),
            target_path.as_mut_ptr(),
            MAX_PATH
        );
        
        if result == 0 {
            return Err(format!("QueryDosDevice failed for {}", device_name));
        }
        
        // Convert wide string to UTF-8
        let len = target_path.iter().position(|&c| c == 0).unwrap_or(0);
        let path = String::from_utf16_lossy(&target_path[..len]);
        Ok(path)
    }
}
