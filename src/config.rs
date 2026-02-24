// config.rs
// Central configuration for sensitive-data detection and false-positive suppression.
// Defines regex patterns loaded once using lazy_static to avoid runtime compilation cost.

use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

// Primary sensitive-data detection patterns.
lazy_static! {
    pub static ref PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        // Detect 16‑digit credit card numbers with optional separators.
        m.insert("card_16", Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap());
        // Detect 15‑digit card formats (Amex-style) with optional separators.
        m.insert("card_15", Regex::new(r"\b\d{4}[- ]?\d{6}[- ]?\d{5}\b").unwrap());
        // Indian mobile numbers with optional +91 prefix.
        m.insert("phone_india", Regex::new(r"\b(\+91[\s-]?)?[6789]\d{9}\b").unwrap());
        // Generic international phone formats with country codes.
        m.insert("phone_with_country", Regex::new(r"\+\d{1,3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{4}\b").unwrap());
        // Common credential-related keywords.
        m.insert("credentials", Regex::new(r"(?i)\b(password|pwd|passcode|login|credential)\b").unwrap());
        // API keys, secrets, and auth token indicators.
        m.insert("keys_tokens", Regex::new(r"(?i)\b(api[_ ]?key|secret|token|auth|bearer)\b").unwrap());
        // Standard email address syntax.
        m.insert("email", Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap());
        // US Social Security Number format.
        m.insert("ssn", Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b").unwrap());
        // Indian Aadhaar number pattern.
        m.insert("aadhaar", Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap());
        // Indian PAN card alphanumeric format.
        m.insert("pan_card", Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b").unwrap());
        m
    };

    // Patterns used to filter out common false positives from OCR noise, documentation,
    // system text, and non-sensitive structured data.
    pub static ref FALSE_POSITIVE_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        // Known test credit card numbers used in documentation/sandbox systems.
        m.insert("test_credit_cards", Regex::new(r"(?i)(4111[- ]?1111[- ]?1111[- ]?1111|5555[- ]?5555[- ]?5555[- ]?4444|3782[- ]?822463[- ]?10005|4242[- ]?4242[- ]?4242[- ]?4242)").unwrap());
        // Numeric sequences that resemble card numbers but are clearly artificial.
        m.insert("sequential_numbers", Regex::new(r"\b(1234[- ]?1234[- ]?1234|1111[- ]?1111[- ]?1111|0000[- ]?0000[- ]?0000|9999[- ]?9999[- ]?9999|2222[- ]?2222[- ]?2222|3333[- ]?3333[- ]?3333)\b").unwrap());
        // Emails targeting example/test domains that should not count as real PII.
        m.insert("example_domains", Regex::new(r"@(example\.com|test\.com|domain\.com|company\.com|sample\.org|email\.com|fake\.com|dummy\.com)").unwrap());
        // Words signaling sample or placeholder text, not real sensitive information.
        m.insert("documentation_keywords", Regex::new(r"(?i)\b(example|sample|test|demo|documentation|placeholder|fictional|dummy|fake|mock|lorem|ipsum)\b").unwrap());
        // Filter lorem ipsum segments often misidentified by OCR.
        m.insert("lorem_ipsum", Regex::new(r"(?i)\b(lorem|ipsum|dolor|sit|amet|consectetur|adipiscing|elit)\b").unwrap());
        // Non-realistic test phone numbers frequently found in documentation.
        m.insert("test_phones", Regex::new(r"(?i)(\+91[\s-]?)?(555[-.]?0100|123[-.]?4567|999[-.]?9999|000[-.]?0000)").unwrap());
        // High-frequency OCR misreads containing repeated ambiguous characters.
        m.insert("ocr_artifacts", Regex::new(r"(?i)[Il|\\/]{4,}|[oO0]{4,}|[Il1]{4,}").unwrap());
        // Timestamps and time-like numeric patterns that resemble IDs.
        m.insert("timestamp_patterns", Regex::new(r"\b(?:\d{8}[-_]?\d{6}|\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}|\d{12,14}|(?:19|20)\d{2}[01]\d[0-3]\d[0-2]\d[0-5]\d[0-5]\d)\b").unwrap());
        // File paths, file names, and typical log/screenshot naming schemes.
        m.insert("file_path_patterns", Regex::new(r"(?i)\b(?:screenshot_\d{8}_\d{6}\.png|logs?/|screenshots?/|certificates?/|\d{4}[-_]\d{2}[-_]\d{2}|[\w/.-]+\.(?:png|jpg|jpeg|json|log|txt|py|js|html?|css|xml|yaml|yml))\b").unwrap());
        // Date formats that can resemble numeric IDs.
        m.insert("date_patterns", Regex::new(r"\b(?:(?:19|20)\d{2}[-/]?(?:0[1-9]|1[0-2])[-/]?(?:0[1-9]|[12][0-9]|3[01])|(?:0[1-9]|[12][0-9]|3[01])[-/]?(?:0[1-9]|1[0-2])[-/]?(?:19|20)\d{2})\b").unwrap());
        // Hexadecimal sequences that appear in logs or hashes but are not PII.
        m.insert("hex_patterns", Regex::new(r"\b[0-9a-fA-F]{8,}\b").unwrap());
        // GPS-style numeric coordinates that should be ignored.
        m.insert("coordinate_patterns", Regex::new(r"\b\d{1,3}\.\d+,\s*\d{1,3}\.\d+\b").unwrap());
        // Code syntax tokens commonly extracted as false positives by OCR.
        m.insert("code_keywords", Regex::new(r"\b(def|class|import|from|return|if|else|for|while|try|except|function|var|let|const|public|private|protected|static|void|print|console\.log|System\.out|printf|echo)\b").unwrap());
        // Python-specific syntax markers to suppress from detection.
        m.insert("python_syntax", Regex::new(r"(__name__|__main__|if __name__|import |from |def |class )").unwrap());
        // System-generated labels, UI text, and scanner metadata.
        m.insert("system_text", Regex::new(r"(?i)\b(?:monitor_optimized|security_log|certificate_|screenshot_|TERMINAL|CONSOLE|PROBLEMS|DEBUG|DELUXE|TEMANAL|violation_count|ocr_extracted|unique_rules|Scan clean|VIOLATION|Status|SENDING LOGS|THREAT ASSESSMENT|CERTIFICATE GENERATED)\b").unwrap());
        // Corrupted OCR fragments that resemble random identifiers.
        m.insert("corrupted_ocr", Regex::new(r"\b(?:[A-Za-z]{1,2}_[A-Za-z]{1,2}|[A-Za-z]\d+[A-Za-z]|[a-z]+[A-Z][a-z]+|[Il1oO0]{3,}|[^A-Za-z0-9\s]{3,})\b").unwrap());
        m
    };
}

// OCR scanning interval in seconds.
pub const OCR_INTERVAL: u64 = 5;
// Retention duration for logs in seconds.
pub const LOG_RETENTION: u64 = 60;

pub static BASE_URLS: Lazy<String> = Lazy::new(|| {
    // std::env::var("DLP_SERVER_URL")
    //     .map(|v| {
    //         v.split(',')
    //             .map(|s| s.trim().to_string())
    //             .collect()
    //     })
    //     .unwrap_or_else(|_| vec![
    //         "http://4.224.156.53:8080".to_string(),
    //         "http://20.193.252.70:8080".to_string(),
    //     ])

      std::env::var("DLP_SERVER_URL").unwrap_or_else(|_| {
        // Try common ports
        // "https://dlp.maximusatlas.com".to_string() // Original Spring Boot port
        // // OR    
        "http://192.168.1.115:9090".to_string()    // Standard HTTP port
        // OR  
        // "http://20.193.252.70".to_string()       // No port (defaults to 80)
    })

});

// pub fn get_primary_server_url() -> String {
//     BASE_URLS
//         .first()
//         .cloned()
//         .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
// }

/// Additional DLP agent configuration constants
pub const SCAN_INTERVAL: u64 = 30; // File system scan interval in seconds
pub const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50MB max file size for scanning
pub const ALLOWED_FILE_TYPES: [&str; 15] = [
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", 
    "csv", "json", "xml", "log", "conf", "config", "yml"
];

/// Network security configuration
pub const BLOCKED_PORTS: [u16; 10] = [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432];
pub const ALLOWED_OUTBOUND_PORTS: [u16; 5] = [80, 443, 53, 8080, 8443];

/// USB device protection
pub const BLOCKED_VID_PIDS: [(&str, &str); 5] = [
    ("0781", "5590"), // Example: SanDisk USB
    ("0951", "1666"), // Example: Kingston USB
    ("13fe", "5500"), // Example: Phison USB
    ("8564", "1000"), // Example: Transcend USB
    ("090c", "1000"), // Example: Silicon Motion USB
];