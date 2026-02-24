use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::policy_constants::{
    FILE_PROTECTION_ENABLED, POLICY_NETWORK_DNS_BLOCK, POLICY_USB_DEVICE_BLOCK,
    POLICY_USB_DEVICE_MONITOR, POLICY_APP_TRACKING, POLICY_BROWSER_MONITOR, POLICY_PARTIAL_ACCESS,
};

/// Represents a single agent capability / policy slot.
/// The backend stores this per-agent and the admin UI reads it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCapability {
    pub code: String,
    pub name: String,
    pub description: String,
    /// Top-level category key used by the admin UI to group policies.
    /// Must be one of: NETWORK, FILE, USB, SECURITY_MONITOR, MONITORING, WEB_MONITOR, FILE_ACCESS
    pub category: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    /// Whether this policy is currently active on this agent.
    #[serde(rename = "isActive")]
    pub is_active: bool,
    /// Optional JSON payload for the policy (e.g., DNS domains list).
    #[serde(rename = "policyData", skip_serializing_if = "Option::is_none")]
    pub policy_data: Option<String>,
}

impl PolicyCapability {
    /// All capabilities this agent supports.
    pub fn all_capabilities() -> Vec<Self> {
        [
            Self::usb_capabilities(),
            Self::network_capabilities(),
            Self::file_capabilities(),
            Self::ocr_capabilities(),
            Self::protection_capabilities(),
        ]
        .concat()
    }

    /// Returns capabilities grouped by category as expected by the admin UI.
    /// Shape: { "NETWORK": [...], "USB": [...], "FILE": [...], "SECURITY_MONITOR": [...] }
    pub fn grouped_by_category(active_codes: &HashMap<String, Option<String>>) -> HashMap<String, Vec<PolicyCapability>> {
        let mut capabilities = Self::all_capabilities();

        // Apply isActive and policyData from the active policy map
        for cap in &mut capabilities {
            if let Some(maybe_data) = active_codes.get(&cap.code) {
                cap.is_active = true;
                cap.policy_data = maybe_data.clone();
            }
        }

        // Group by category
        let mut grouped: HashMap<String, Vec<PolicyCapability>> = HashMap::new();
        for cap in capabilities {
            grouped.entry(cap.category.clone()).or_default().push(cap);
        }
        grouped
    }

    /// USB protection policies
    pub fn usb_capabilities() -> Vec<Self> {
        vec![
            PolicyCapability {
                code: POLICY_USB_DEVICE_BLOCK.to_string(),
                name: "Block All USB Drives".to_string(),
                description: "Completely block all USB storage devices from being used.".to_string(),
                category: "USB".to_string(),
                action: "BLOCK".to_string(),
                target: "ALL_USB_STORAGE".to_string(),
                severity: "HIGH".to_string(),
                is_active: false,
                policy_data: None,
            },
            PolicyCapability {
                code: POLICY_USB_DEVICE_MONITOR.to_string(),
                name: "Monitor USB Connections".to_string(),
                description: "Create an alert whenever a USB device is connected or disconnected.".to_string(),
                category: "USB".to_string(),
                action: "MONITOR".to_string(),
                target: "USB_CONNECTIONS".to_string(),
                severity: "LOW".to_string(),
                is_active: false,
                policy_data: None,
            },
        ]
    }

    /// Network / DNS protection policies
    pub fn network_capabilities() -> Vec<Self> {
        vec![PolicyCapability {
            code: POLICY_NETWORK_DNS_BLOCK.to_string(),
            name: "DNS Filtering (Domain Block)".to_string(),
            description: "Block specific domains/IPs by adding them to the Windows firewall.".to_string(),
            category: "NETWORK".to_string(),
            action: "BLOCK".to_string(),
            target: "DOMAINS_IPS".to_string(),
            severity: "HIGH".to_string(),
            is_active: false,
            policy_data: None,
        }]
    }

    /// File protection policies
    pub fn file_capabilities() -> Vec<Self> {
        vec![PolicyCapability {
            code: FILE_PROTECTION_ENABLED.to_string(),
            name: "File Protection System".to_string(),
            description: "Complete filesystem protection with kernel-level enforcement.".to_string(),
            category: "FILE".to_string(),
            action: "ENFORCE".to_string(),
            target: "FILESYSTEM".to_string(),
            severity: "HIGH".to_string(),
            is_active: false,
            policy_data: None,
        }]
    }

    /// OCR / screen monitoring policies — must use SECURITY_MONITOR as category key
    pub fn ocr_capabilities() -> Vec<Self> {
        vec![PolicyCapability {
            code: "POLICY_OCR_MONITOR".to_string(),
            name: "OCR Screen Monitoring".to_string(),
            description: "Monitor screenshots for sensitive data using OCR.".to_string(),
            category: "SECURITY_MONITOR".to_string(),
            action: "MONITOR".to_string(),
            target: "SCREEN_CONTENT".to_string(),
            severity: "MEDIUM".to_string(),
            is_active: false,
            policy_data: None,
        }]
    }

    /// App tracking, browser monitoring, partial access
    pub fn protection_capabilities() -> Vec<Self> {
        vec![
            PolicyCapability {
                code: POLICY_APP_TRACKING.to_string(),
                name: "Application Usage Tracking".to_string(),
                description: "Monitors and reports the time spent in each application.".to_string(),
                category: "MONITORING".to_string(),
                action: "MONITOR".to_string(),
                target: "APPS".to_string(),
                severity: "LOW".to_string(),
                is_active: false,
                policy_data: None,
            },
            PolicyCapability {
                code: POLICY_BROWSER_MONITOR.to_string(),
                name: "Browser URL Monitoring".to_string(),
                description: "Extracts and reports URLs from browsers and enforces blacklists.".to_string(),
                category: "WEB_MONITOR".to_string(),
                action: "ENFORCE".to_string(),
                target: "URLS".to_string(),
                severity: "MEDIUM".to_string(),
                is_active: false,
                policy_data: None,
            },
            PolicyCapability {
                code: POLICY_PARTIAL_ACCESS.to_string(),
                name: "Partial Access Control".to_string(),
                description: "Blocks file upload/download dialogs based on site policies.".to_string(),
                category: "FILE_ACCESS".to_string(),
                action: "BLOCK".to_string(),
                target: "DIALOGS".to_string(),
                severity: "HIGH".to_string(),
                is_active: false,
                policy_data: None,
            },
        ]
    }
}