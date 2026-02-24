use chrono::{DateTime, Utc};
// Core data structures used across OCR, rule evaluation, context analysis, logging,
// and certificate generation. Defines strongly typed models for all major pipeline stages.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Configuration model for each detection rule: pattern, context requirements, and scoring settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub name: String,
    pub pattern: String,
    pub confidence: f32,
    pub context_window: usize,
    pub context_sensitive: bool,
    pub required_context: Option<Vec<String>>,
    pub forbidden_context: Option<Vec<String>>,
}

// Raw violation emitted by rule engine: includes matched text, location, confidence, and context clues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule_type: String,
    pub confidence: f32,
    pub matched_text: String,
    pub x: i32,
    pub y: i32,
    pub context_confidence: f32,
    pub surrounding_text: String,
    pub contextual_clues: Vec<String>,
    
}

// Unified log record written for each processed frame, containing OCR output,
// rule hits, context metadata, and operational markers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub event: String,
    pub timestamp: String,
    pub device: String,
    pub mac: String,
    pub violation_count: u32,
    pub rules_detected: usize,
    pub screenshot: String,
    pub hits: Vec<Hit>,
    pub text_sample: String,
    pub rule_engine_used: bool,
    pub ocr_quality: String,
    pub nlp_context: TextContext,
}

// Normalized violation unit used inside logs and certificate generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub rule: String,
    pub x: i32,
    pub y: i32,
    pub flagged_text: String,
    pub context_confidence: f32,
    pub contextual_evidence: Vec<String>,
}

// Final security certificate summarizing threat score, detected behaviors,
// recommended actions, and contextual risk analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_id: String,
    pub user_device: String,
    pub user_mac: String,
    pub assessment_time: String,
    pub assessment_method: String,
    pub llm_available: bool,
    pub threat_score: f32,
    pub threat_level: String,
    pub risk_analysis: String,
    pub behavior_insights: String,
    pub immediate_actions: Vec<String>,
    pub training_recommendations: Vec<String>,
    pub total_violations: usize,
    pub unique_rule_types: usize,
    pub rule_breakdown: HashMap<String, usize>,
    pub color_code: String,
    pub emoji: String,
    pub context_analysis: ContextAnalysis,
}

// Aggregated multi-frame NLP context analysis used to infer dominant domain and behavior patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnalysis {
    pub primary_context: String,
    pub risk_factors: Vec<String>,
    pub behavioral_patterns: Vec<String>,
    pub confidence_score: f32,
}

// Full OCR output: raw text, per-word metadata, and computed textual context.
#[derive(Debug, Clone)]
pub struct OcrData {
    pub text: String,
    pub words: Vec<WordData>,
    pub context: TextContext,
}

// Lightweight NLP-derived context features computed from extracted text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContext {
    pub language: String,
    pub is_financial: bool,
    pub is_technical: bool,
    pub is_personal: bool,
    pub is_business: bool,
    pub contains_names: bool,
    pub sentence_count: usize,
    pub avg_sentence_length: f32,
    pub readability_score: f32,
}

// Per-token OCR metadata including approximate bounding box, confidence, and local context window.
#[derive(Debug, Clone)]
pub struct WordData {
    pub text: String,
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
    pub confidence: f32,
    pub surrounding_context: String,
}



// src/protection_modules/security_monitor/types.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeUpdate {
    pub update_type: UpdateType,
    pub timestamp: String,
    pub agent_id: u64,
    pub data: UpdateData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateType {
    ScreenshotCaptured,
    ViolationDetected,
    CertificateGenerated,
    StatusUpdate,
    PerformanceMetrics,
    MaintenanceCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateData {
    Screenshot(ScreenshotData),
    Violation(ViolationUpdate),
    Certificate(CertificateSummary),
    Status(AgentStatus),
    Metrics(PerformanceUpdate),
    Maintenance(MaintenanceLog),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotData {
    pub path: String,
    pub dimensions: (u32, u32),
    pub size_kb: f32,
    pub preview_url: Option<String>, // Base64 thumbnail
    pub timestamp: DateTime<Utc>,  // Add this field
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationUpdate {
    pub id: String,
    pub rule_type: String,
    pub matched_text: String,
    pub confidence: f32,
    pub context_confidence: f32,
    pub screenshot_path: String,
    pub timestamp: String,
    pub contextual_clues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub certificate_id: String,
    pub generation_time: String,
    pub threat_score: f32,
    pub threat_level: String,
    pub total_violations: usize,
    pub primary_context: String,
    pub color_code: String,
    pub emoji: String,
    pub download_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub enabled: bool,
    pub last_activity: String,
    pub violations_today: u32,
    pub screenshots_today: u32,
    pub certificates_today: u32,
    pub current_settings: MonitorSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSettings {
    pub ocr_interval: u64,
    pub cleanup_screenshots_after: u64,
    pub cleanup_certificates_after: u64,
    pub cleanup_logs_after: u64,
    pub llm_enabled: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceUpdate {
    pub frames_processed: u64,
    pub text_detection_rate: f64,
    pub avg_processing_time: f64,
    pub cpu_usage: f32,
    pub memory_usage_mb: f32,
    pub disk_usage_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceLog {
    pub action: String,
    pub details: String,
    pub files_cleaned: u32,
    pub space_freed_mb: f32,
}