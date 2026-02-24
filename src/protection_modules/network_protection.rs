use crate::policy_engine::PolicyEngine;
use crate::communication::ServerCommunicator;
use crate::protection_modules::ProtectionModule;
use super::super::policy_constants::*;
use serde::Deserialize;
use std::any::Any;
use std::collections::{BTreeSet, HashSet};
use log::{info, warn, error};
use std::hash::{Hash};
use std::error::Error;
use std::ptr;
use std::mem;
use std::ffi::c_void;

// --- Windows Filtering Platform (WFP) Imports ---
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineOpen0, FwpmEngineClose0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0,
    FWPM_SESSION0, FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWP_ACTION_BLOCK, FWP_MATCH_EQUAL, FWP_V4_ADDR_AND_MASK, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SESSION_FLAG_DYNAMIC, FWP_V4_ADDR_MASK, FWP_CONDITION_VALUE0, FWPM_ACTION0,
    FWPM_FILTER_CONDITION0
};
use windows_sys::Win32::System::Rpc::{RpcMgmtWaitServerListen, RPC_C_AUTHN_WINNT};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

// Thread-safe wrapper for WFP handle
struct WfpHandle(*mut c_void);
unsafe impl Send for WfpHandle {}
unsafe impl Sync for WfpHandle {}

const DLP_AGENT_SUBLAYER_GUID: GUID = GUID {
    data1: 0x8a815a51, data2: 0x9303, data3: 0x4e8b, data4: [0x95, 0x2e, 0x48, 0x2e, 0x44, 0x5e, 0x76, 0x01],
};

#[derive(Deserialize, Debug, Clone, Default)]
struct NetworkPolicyData {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
}

// ===== NETWORK PROTECTION MODULE =====
pub struct NetworkProtection {
    wfp_engine_handle: WfpHandle,
    last_policy_hash: u64,
    active_filter_keys: Vec<GUID>,
}

impl NetworkProtection {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        info!("Initializing Network Protection Module (WFP)...");
        let result = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
        if result < 0 {
            return Err(format!("Failed to initialize COM. Error code: {}", result).into());
        }
        let handle = Self::initialize_wfp_session()?;
        
        info!("✅ Network Protection Module connected to Windows Filtering Platform.");
        Ok(Self {
            wfp_engine_handle: WfpHandle(handle),
            last_policy_hash: 0,
            active_filter_keys: Vec::new(),
        })
    }

    async fn enforce_dns_policy(&mut self, policy_engine: &PolicyEngine) -> Result<(), Box<dyn Error + Send + Sync>> {
        let policy_data: NetworkPolicyData = policy_engine.get_policy_json_data(POLICY_NETWORK_DNS_BLOCK);
        let mut new_blocked_entries = BTreeSet::new();
        for domain in policy_data.domains { new_blocked_entries.insert(domain); }
        for ip in policy_data.ips { new_blocked_entries.insert(ip); }

        let new_hash = {
            let mut s = std::hash::DefaultHasher::new();
            new_blocked_entries.hash(&mut s);
            std::hash::Hasher::finish(&s)
        };

        if new_hash == self.last_policy_hash {
            return Ok(());
        }

        info!("🛡️ New network policy detected. Applying WFP rules...");
        self.clear_wfp_rules()?;
        let ips_to_block = self.resolve_domains_to_ips(new_blocked_entries).await;
        info!("Resolved to {} unique IP addresses for blocking.", ips_to_block.len());

        for ip in &ips_to_block {
            match self.add_wfp_block_rule(ip) {
                Ok(filter_key) => self.active_filter_keys.push(filter_key),
                Err(e) => error!("Failed to add block rule for IP {}: {}", ip, e),
            }
        }
        
        self.last_policy_hash = new_hash;
        Ok(())
    }

    async fn resolve_domains_to_ips(&self, entries: BTreeSet<String>) -> HashSet<String> {
        let mut ips = HashSet::new();
        for entry in entries {
            if entry.parse::<std::net::IpAddr>().is_ok() {
                ips.insert(entry);
            } else {
                let addr_with_port = format!("{}:80", entry);
                if let Ok(addresses) = tokio::net::lookup_host(addr_with_port).await {
                    for addr in addresses {
                        if addr.is_ipv4() {
                            ips.insert(addr.ip().to_string());
                        }
                    }
                } else {
                    warn!("Could not resolve domain '{}'", entry);
                }
            }
        }
        ips
    }

    // --- ENTERPRISE WFP ENGINE ---

    fn initialize_wfp_session() -> Result<*mut c_void, Box<dyn Error + Send + Sync>> {
        let mut session_name: Vec<u16> = "DLP Agent Session".encode_utf16().collect();
        session_name.push(0);
        let mut session_desc: Vec<u16> = "DLP agent session".encode_utf16().collect();
        session_desc.push(0);
        
        // Generate session key
        let mut session_key = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
        unsafe {
            windows_sys::Win32::System::Com::CoCreateGuid(&mut session_key);
        }
        
        let session = FWPM_SESSION0 {
            sessionKey: session_key,
            displayData: FWPM_DISPLAY_DATA0 { 
                name: session_name.as_mut_ptr(), 
                description: session_desc.as_mut_ptr() 
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 0,
            processId: 0,
            sid: ptr::null_mut(),
            username: ptr::null_mut(),
            kernelMode: 0,
        };

        let mut engine_handle: *mut c_void = ptr::null_mut();
        let result = unsafe {
            RpcMgmtWaitServerListen();
            FwpmEngineOpen0(
                ptr::null(), 
                RPC_C_AUTHN_WINNT, 
                ptr::null(), 
                &session, 
                &mut engine_handle as *mut _ as *mut isize
            )
        };

        if result as u32 != ERROR_SUCCESS {
            return Err(format!("WFP Connection Failed: {}. Are you running as Administrator?", result).into());
        }

        let mut sublayer_name: Vec<u16> = "DLP Agent SubLayer".encode_utf16().collect();
        sublayer_name.push(0);
        let mut sublayer_desc: Vec<u16> = "Sublayer for DLP agent network rules".encode_utf16().collect();
        sublayer_desc.push(0);

        // Create empty provider data (FWPM_BYTE_BLOB equivalent)
        let provider_data_size = 0;
        let provider_data_ptr = ptr::null_mut();

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: DLP_AGENT_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: sublayer_name.as_mut_ptr(),
                description: sublayer_desc.as_mut_ptr(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            weight: 0xFFFF,
            providerKey: ptr::null_mut(),
            providerData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
                size: provider_data_size,
                data: provider_data_ptr,
            },
        };

        let result = unsafe { 
            FwpmSubLayerAdd0(
                engine_handle as isize, 
                &sublayer, 
                ptr::null_mut()
            ) 
        };
        
        if result as u32 != ERROR_SUCCESS {
            warn!("Failed to add WFP sublayer (it might already exist). Code: {}", result);
        }

        Ok(engine_handle)
    }

    fn clear_wfp_rules(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Clearing {} old WFP rules...", self.active_filter_keys.len());
        for key in &self.active_filter_keys {
            let result = unsafe { 
                FwpmFilterDeleteByKey0(
                    self.wfp_engine_handle.0 as isize, 
                    key
                ) 
            };
            if result as u32 != ERROR_SUCCESS {
                warn!("Failed to delete WFP filter. Code: {}", result);
            }
        }
        self.active_filter_keys.clear();
        Ok(())
    }

    fn add_wfp_block_rule(&self, ip_address: &str) -> Result<GUID, Box<dyn Error>> {
    let ip_addr: std::net::Ipv4Addr = ip_address.parse()?;
    let ip_addr_bytes = ip_addr.octets();

    let filter_key = unsafe {
        let mut guid = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
        windows_sys::Win32::System::Com::CoCreateGuid(&mut guid);
        guid
    };

    let mut addr_mask = FWP_V4_ADDR_AND_MASK {
        addr: u32::from_be_bytes(ip_addr_bytes),
        mask: 0xFFFFFFFF,
    };
    
    // FIX: Use correct field name 'type' instead of 'conditionType'
    let mut condition_value: FWP_CONDITION_VALUE0 = unsafe { mem::zeroed() };
    condition_value.r#type = FWP_V4_ADDR_MASK; // Use 'type' field
    
    unsafe {
        // Set the union field correctly
        *(&mut condition_value.Anonymous.v4AddrMask as *mut _ as *mut *mut FWP_V4_ADDR_AND_MASK) = &mut addr_mask;
    }
    
    // Create filter condition
    let mut filter_condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: condition_value,
    };

    // Create action - use 'type' field instead of 'actionType'
    let mut action: FWPM_ACTION0 = unsafe { mem::zeroed() };
    action.r#type = FWP_ACTION_BLOCK; // Use 'type' field
    
    let mut filter_name: Vec<u16> = format!("DLP Block: {}", ip_address).encode_utf16().collect();
    filter_name.push(0);

    // Create the main filter
    let mut filter: FWPM_FILTER0 = unsafe { mem::zeroed() };
    filter.filterKey = filter_key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: filter_name.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = DLP_AGENT_SUBLAYER_GUID;
    
    // FIX: Use correct weight structure - use 'r#type' not 'type_'
    filter.weight.r#type = 0; // FWP_UINT8
    filter.weight.Anonymous.uint8 = 0xFF; // Set weight value
    
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut filter_condition;
    filter.action = action;
    filter.flags = 0;

    let result = unsafe { 
        FwpmFilterAdd0(
            self.wfp_engine_handle.0 as isize, 
            &filter, 
            ptr::null_mut(), 
            ptr::null_mut()
        ) 
    };
    
    if result as u32 != ERROR_SUCCESS {
        return Err(format!("Failed to add WFP filter for {}. Error: {}", ip_address, result).into());
    }

    info!("✅ Added WFP block rule for IP: {}", ip_address);
    Ok(filter_key)
}

}

impl Drop for NetworkProtection {
    fn drop(&mut self) {
        if !self.wfp_engine_handle.0.is_null() {
            info!("Shutting down Network Protection. Clearing rules and closing WFP handle...");
            if let Err(e) = self.clear_wfp_rules() {
                error!("Failed to clear WFP rules on shutdown: {}", e);
            }
            unsafe {
                FwpmSubLayerDeleteByKey0(
                    self.wfp_engine_handle.0 as isize, 
                    &DLP_AGENT_SUBLAYER_GUID
                );
                FwpmEngineClose0(self.wfp_engine_handle.0 as isize);
                CoUninitialize();
            };
        }
    }
}

// ===== PROTECTION MODULE IMPLEMENTATION =====
#[async_trait::async_trait]
impl ProtectionModule for NetworkProtection {
    async fn execute(
        &mut self,
        policy_engine: &PolicyEngine,
        _communicator: &ServerCommunicator,
        _agent_id: u64,
        _token: &str
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        
        if policy_engine.is_policy_active(POLICY_NETWORK_DNS_BLOCK) {
            self.enforce_dns_policy(policy_engine).await?;
        } else {
            if self.last_policy_hash != 0 {
                info!("🧹 Network policy disabled. Cleaning up WFP rules...");
                self.clear_wfp_rules()?;
                self.last_policy_hash = 0;
            }
        }
        Ok(())
    }

    fn get_name(&self) -> &str { "Network" }

     fn as_any(&self) -> &dyn Any {
        self
    }
}