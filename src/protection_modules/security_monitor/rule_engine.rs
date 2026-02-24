// Rule engine: applies regex-based detection, semantic validation, and context-aware scoring
// to classify high-risk PII while suppressing false positives from OCR/system noise.
use crate::config::{PATTERNS, FALSE_POSITIVE_PATTERNS};
use crate::protection_modules::security_monitor::types::{Violation, OcrData, TextContext};
use regex::Regex;
use std::collections::HashSet;
// Add this import at the top of rule_engine.rs
use std::time:: {Duration,Instant};

// Main rule evaluation unit coordinating compiled rules and context validator.
pub struct SecurityRuleEngine {
    rules: Vec<SecurityRule>,
    context_analyzer: ContextAwareValidator,

     recent_violations_cache: HashSet<String>,  // Store "rule_type:normalized_text"
    cache_expiry_times: Vec<(String, Instant)>, // For cleanup
    cache_duration: Duration,
    seen_in_current_screenshot: HashSet<String>, // ✅ Track within current screenshot
}

// Represents a single detection rule with regex pattern, validator function, and scoring parameters.
struct SecurityRule {
    name: String,
    pattern: Regex,
    validator: fn(&str, &str, &TextContext, &ContextAwareValidator) -> (bool, f32, Vec<String>),
    base_confidence: f32,
    context_boost: f32,
}

// Provides keyword-driven contextual scoring to boost or suppress matches based on domain signals.
struct ContextAwareValidator {
    financial_indicators: Vec<&'static str>,
    personal_indicators: Vec<&'static str>,
    business_indicators: Vec<&'static str>,
    low_risk_indicators: Vec<&'static str>,
}

impl ContextAwareValidator {
    fn new() -> Self {
        Self {
            financial_indicators: vec![
                "account", "bank", "payment", "transaction", "balance", "transfer",
                "fund", "money", "credit", "debit", "invoice", "receipt"
            ],
            personal_indicators: vec![
                "my", "personal", "private", "home", "family", "friend",
                "birthday", "anniversary", "photo", "picture"
            ],
            business_indicators: vec![
                "company", "corporate", "business", "enterprise", "organization",
                "client", "customer", "vendor", "supplier", "invoice"
            ],
            low_risk_indicators: vec![
                "example", "sample", "test", "demo", "placeholder", "fictional",
                "documentation", "tutorial", "learning", "practice"
            ],
        }
    }

    // Computes rule-specific confidence multipliers using domain keywords, local text window, and readability.
    fn analyze_context_confidence(&self, matched_text: &str, full_text: &str, context: &TextContext) -> (f32, Vec<String>) {
        let mut confidence: f32 = 1.0; 
        let mut clues = Vec::new();
        let text_lower = full_text.to_lowercase();

        // Check for high-risk context matches
        if context.is_financial {
            if self.financial_indicators.iter().any(|&indicator| text_lower.contains(indicator)) {
                confidence *= 1.3;
                clues.push("Found in financial context".to_string());
            }
        }

        if context.is_personal {
            if self.personal_indicators.iter().any(|&indicator| text_lower.contains(indicator)) {
                confidence *= 1.2;
                clues.push("Found in personal context".to_string());
            }
        }

        // Check for low-risk indicators
        if self.low_risk_indicators.iter().any(|&indicator| text_lower.contains(indicator)) {
            confidence *= 0.3;
            clues.push("Low-risk context detected".to_string());
        }

        // Analyze surrounding text for contextual clues
        let surrounding_clues = self.analyze_surrounding_text(matched_text, full_text);
        clues.extend(surrounding_clues);

        // Adjust based on readability (complex text might be more legitimate)
        if context.readability_score < 30.0 { // Very simple text
            confidence *= 0.8;
            clues.push("Very simple text - possible test content".to_string());
        }

        // FIX: Return the tuple with both confidence and clues
        (confidence.max(0.1).min(2.0), clues) // Cap between 0.1 and 2.0
    }

    // Looks at nearby words to identify explicit PII-related context hints.
    fn analyze_surrounding_text(&self, matched_text: &str, full_text: &str) -> Vec<String> {
        let mut clues = Vec::new();
        let words: Vec<&str> = full_text.split_whitespace().collect();
        
        if let Some(pos) = words.iter().position(|&w| w == matched_text) {
            let start = pos.saturating_sub(5);
            let end = (pos + 6).min(words.len());
            let context_words = &words[start..end];
            let context_text = context_words.join(" ").to_lowercase();

            // Look for contextual patterns
            if context_text.contains("card number") || context_text.contains("credit card") {
                clues.push("Explicit credit card context".to_string());
            }
            
            if context_text.contains("social security") || context_text.contains("ssn") {
                clues.push("Explicit SSN context".to_string());
            }
            
            if context_text.contains("aadhaar") || context_text.contains("uidai") {
                clues.push("Explicit Aadhaar context".to_string());
            }
            
            if context_text.contains("pan card") || context_text.contains("permanent account") {
                clues.push("Explicit PAN context".to_string());
            }
        }

        clues
    }

    // Semantic reinforcement based on digit patterns aligning with known PII structures.
    fn validate_semantic_context(&self, matched_text: &str, full_text: &str) -> f32 {
        let text_lower = full_text.to_lowercase();
        let mut semantic_score = 1.0;

        // Credit card semantic validation
        if matched_text.chars().filter(|c| c.is_ascii_digit()).count() == 16 {
            let card_contexts = ["card", "credit", "debit", "number", "expiry", "cvv"];
            if card_contexts.iter().any(|&ctx| text_lower.contains(ctx)) {
                semantic_score *= 1.5;
            }
        }

        // SSN semantic validation
        if matched_text.chars().filter(|c| c.is_ascii_digit()).count() == 9 {
            let ssn_contexts = ["social", "security", "ssn", "tax", "identification"];
            if ssn_contexts.iter().any(|&ctx| text_lower.contains(ctx)) {
                semantic_score *= 1.4;
            }
        }

        semantic_score
    }
}

impl SecurityRuleEngine {
    pub fn new() -> Self {
        let mut engine = Self { 
            rules: Vec::new(),
            context_analyzer: ContextAwareValidator::new(),
             recent_violations_cache: HashSet::new(),
            cache_expiry_times: Vec::new(),
            cache_duration: Duration::from_secs(120), // Remember for 120 seconds
              seen_in_current_screenshot: HashSet::new(),
        };
        engine.compile_rules();
        engine
    }

        // ✅ NEW: Reset for each screenshot
            pub fn reset_for_screenshot(&mut self) {
                self.seen_in_current_screenshot.clear();
            }  
      // ✅ NEW: Check if we've seen this violation recently
    fn is_recent_duplicate(&mut self, rule_type: &str, matched_text: &str) -> bool {
        self.cleanup_expired_cache();
        
        let normalized = Self::normalize_violation_key(rule_type, matched_text);
        let is_duplicate = self.recent_violations_cache.contains(&normalized);
        
        if !is_duplicate {
            // Store in cache
            self.recent_violations_cache.insert(normalized.clone());
            self.cache_expiry_times.push((normalized, Instant::now()));
        }
        
        is_duplicate
    }
    
     // ✅ NEW: Clean up old cache entries
    fn cleanup_expired_cache(&mut self) {
        let now = Instant::now();
        self.cache_expiry_times.retain(|(key, timestamp)| {
            if now.duration_since(*timestamp) < self.cache_duration {
                true
            } else {
                self.recent_violations_cache.remove(key);
                false
            }
        });
    }
    
    // ✅ NEW: Normalize text for comparison
    fn normalize_violation_key(rule_type: &str, text: &str) -> String {
        // Remove spaces and special chars for comparison
        let normalized_text: String = text
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        
        format!("{}:{}", rule_type, normalized_text)
    }
    
    // Builds all rule definitions by binding patterns, validators, and base scoring.
    fn compile_rules(&mut self) {
        // Credit card rule with context awareness
        self.rules.push(SecurityRule {
            name: "credit_card".to_string(),
            pattern: PATTERNS["card_16"].clone(),
            validator: Self::validate_credit_card_context,
            base_confidence: 0.9,
            context_boost: 0.3,
        });

        // SSN rule with context awareness
        self.rules.push(SecurityRule {
            name: "ssn".to_string(),
            pattern: PATTERNS["ssn"].clone(),
            validator: Self::validate_ssn_context,
            base_confidence: 0.8,
            context_boost: 0.4,
        });

        // Aadhaar rule with context awareness
        self.rules.push(SecurityRule {
            name: "aadhaar_card".to_string(),
            pattern: PATTERNS["aadhaar"].clone(),
            validator: Self::validate_aadhaar_context,
            base_confidence: 0.8,
            context_boost: 0.4,
        });

        // PAN card rule with context awareness
        self.rules.push(SecurityRule {
            name: "pan_card".to_string(),
            pattern: PATTERNS["pan_card"].clone(),
            validator: Self::validate_pan_context,
            base_confidence: 0.85,
            context_boost: 0.35,
        });

        // Email rule with context awareness
        self.rules.push(SecurityRule {
            name: "email_sensitive".to_string(),
            pattern: PATTERNS["email"].clone(),
            validator: Self::validate_sensitive_email_context,
            base_confidence: 0.8,
            context_boost: 0.5,
        });
    }

    // Validator: applies false-positive filters, semantic heuristics, and contextual boosts.
    fn validate_credit_card_context(
        matched_text: &str, 
        full_text: &str, 
        context: &TextContext,
        context_validator: &ContextAwareValidator
    ) -> (bool, f32, Vec<String>) {
        if Self::is_system_or_code_text(full_text) {
            return (false, 0.0, vec!["System/code text detected".to_string()]);
        }

        let card_digits: String = matched_text.chars().filter(|c| c.is_ascii_digit()).collect();
        
        // Skip test numbers
        if FALSE_POSITIVE_PATTERNS["test_credit_cards"].is_match(matched_text) {
            return (false, 0.0, vec!["Test credit card pattern".to_string()]);
        }

        // Skip sequential numbers
        if FALSE_POSITIVE_PATTERNS["sequential_numbers"].is_match(matched_text) {
            return (false, 0.0, vec!["Sequential number pattern".to_string()]);
        }

        // Skip if all digits are the same
        if card_digits.chars().all(|c| c == card_digits.chars().next().unwrap()) {
            return (false, 0.0, vec!["All digits identical".to_string()]);
        }

        // Skip OCR artifacts
        if FALSE_POSITIVE_PATTERNS["ocr_artifacts"].is_match(matched_text) {
            return (false, 0.0, vec!["OCR artifact detected".to_string()]);
        }

        // Skip timestamps and file patterns
        if FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(matched_text) ||
           FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(full_text) {
            return (false, 0.0, vec!["Timestamp/file pattern".to_string()]);
        }

        // Validate with Luhn algorithm
        let luhn_valid = if card_digits.len() == 16 {
            Self::luhn_check(&card_digits)
        } else {
            false
        };

        if !luhn_valid {
            return (false, 0.0, vec!["Luhn check failed".to_string()]);
        }

        // Context analysis
        let (context_confidence, context_clues) = context_validator.analyze_context_confidence(
            matched_text, full_text, context
        );
        let semantic_boost = context_validator.validate_semantic_context(matched_text, full_text);

        let final_confidence = 0.9 * context_confidence * semantic_boost;

        (true, final_confidence, context_clues)
    }

    // Validator: applies false-positive filters, semantic heuristics, and contextual boosts.
    fn validate_ssn_context(
        matched_text: &str, 
        full_text: &str, 
        context: &TextContext,
        context_validator: &ContextAwareValidator
    ) -> (bool, f32, Vec<String>) {
        if Self::is_system_or_code_text(full_text) {
            return (false, 0.0, vec!["System/code text detected".to_string()]);
        }

        let digits: String = matched_text.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits == "000000000" || digits == "123456789" || digits == "111111111" || digits == "999999999" {
            return (false, 0.0, vec!["Invalid SSN pattern".to_string()]);
        }

        // Check for documentation context
        if FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(full_text) {
            return (false, 0.0, vec!["Documentation context".to_string()]);
        }

        // Check for OCR artifacts
        if FALSE_POSITIVE_PATTERNS["ocr_artifacts"].is_match(matched_text) {
            return (false, 0.0, vec!["OCR artifact".to_string()]);
        }

        // Skip timestamps, file patterns, and coordinates
        if FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(matched_text) ||
           FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(full_text) ||
           FALSE_POSITIVE_PATTERNS["coordinate_patterns"].is_match(full_text) ||
           FALSE_POSITIVE_PATTERNS["hex_patterns"].is_match(matched_text) {
            return (false, 0.0, vec!["System pattern match".to_string()]);
        }

        // Additional SSN validation
        if digits.len() != 9 {
            return (false, 0.0, vec!["Invalid length".to_string()]);
        }
        
        let first_three = &digits[0..3];
        if first_three == "000" || first_three == "666" {
            return (false, 0.0, vec!["Invalid area number".to_string()]);
        }

        if let Ok(num) = first_three.parse::<u16>() {
            if (900..=999).contains(&num) {
                return (false, 0.0, vec!["Invalid area number range".to_string()]);
            }
        }

        // Context analysis
        let (context_confidence, context_clues) = context_validator.analyze_context_confidence(
            matched_text, full_text, context
        );
        let semantic_boost = context_validator.validate_semantic_context(matched_text, full_text);

        let final_confidence = 0.8 * context_confidence * semantic_boost;

        (true, final_confidence, context_clues)
    }

    // Validator: applies false-positive filters, semantic heuristics, and contextual boosts.
    fn validate_aadhaar_context(
        matched_text: &str, 
        full_text: &str, 
        context: &TextContext,
        context_validator: &ContextAwareValidator
    ) -> (bool, f32, Vec<String>) {
        {
            if Self::is_system_or_code_text(full_text) {
                return (false, 0.0, vec!["System/code text detected".to_string()]);
            }

            let digits: String = matched_text.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() != 12 {
                return (false, 0.0, vec!["Invalid Aadhaar length".to_string()]);
            }

            if FALSE_POSITIVE_PATTERNS["ocr_artifacts"].is_match(matched_text)
                || FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(matched_text)
                || FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(full_text)
                || FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(full_text)
            {
                return (false, 0.0, vec!["False-positive context".to_string()]);
            }

            let (ctx_conf, clues) = context_validator.analyze_context_confidence(matched_text, full_text, context);
            let semantic_boost = if full_text.to_lowercase().contains("aadhaar")
                || full_text.to_lowercase().contains("uidai")
                || full_text.to_lowercase().contains("identity")
            {
                1.4
            } else {
                1.0
            };

            let final_conf = 0.8 * ctx_conf * semantic_boost;
            (true, final_conf, clues)
        }
    }

    // Validator: applies false-positive filters, semantic heuristics, and contextual boosts.
    fn validate_pan_context(
        matched_text: &str, 
        full_text: &str, 
        context: &TextContext,
        context_validator: &ContextAwareValidator
    ) -> (bool, f32, Vec<String>) {
        {
            if Self::is_system_or_code_text(full_text) {
                return (false, 0.0, vec!["System/code text detected".to_string()]);
            }

            let pan = matched_text.trim();
            if pan.len() != 10 {
                return (false, 0.0, vec!["Invalid PAN length".to_string()]);
            }

            let valid_struct = regex::Regex::new(r"^[A-Z]{5}[0-9]{4}[A-Z]$").unwrap();
            if !valid_struct.is_match(pan) {
                return (false, 0.0, vec!["Invalid PAN format".to_string()]);
            }

            if FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(full_text)
                || FALSE_POSITIVE_PATTERNS["ocr_artifacts"].is_match(pan)
            {
                return (false, 0.0, vec!["False-positive context".to_string()]);
            }

            let (ctx_conf, clues) = context_validator.analyze_context_confidence(pan, full_text, context);
            let semantic_boost = if full_text.to_lowercase().contains("pan")
                || full_text.to_lowercase().contains("account")
            {
                1.4
            } else {
                1.0
            };

            let final_conf = 0.85 * ctx_conf * semantic_boost;
            (true, final_conf, clues)
        }
    }

    // Validator: applies false-positive filters, semantic heuristics, and contextual boosts.
    fn validate_sensitive_email_context(
        matched_text: &str, 
        full_text: &str, 
        context: &TextContext,
        context_validator: &ContextAwareValidator
    ) -> (bool, f32, Vec<String>) {
        {
            if Self::is_system_or_code_text(full_text) {
                return (false, 0.0, vec!["System/code text detected".to_string()]);
            }

            let email = matched_text.trim().to_lowercase();
            let sensitive_domains = ["gov", "bank", "finance", "corp", "secure", "internal"];
            let mut clues = Vec::new();
            let mut score = 1.0;

            if sensitive_domains.iter().any(|d| email.contains(d)) {
                score *= 1.5;
                clues.push("High-risk email domain".to_string());
            }

            if FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(full_text)
                || FALSE_POSITIVE_PATTERNS["ocr_artifacts"].is_match(&email)
            {
                return (false, 0.0, vec!["False-positive context".to_string()]);
            }

            let (ctx_conf, ctx_clues) = context_validator.analyze_context_confidence(&email, full_text, context);
            clues.extend(ctx_clues);

            let final_conf = 0.6 * ctx_conf * score;
            (true, final_conf, clues)
        }
    }

    // Suppresses rule-triggering on system logs, code snippets, timestamps, and corrupted OCR fragments.
    fn is_system_or_code_text(text: &str) -> bool {
        let text_lower = text.to_lowercase();
        
        FALSE_POSITIVE_PATTERNS["system_text"].is_match(&text_lower) ||
        FALSE_POSITIVE_PATTERNS["code_keywords"].is_match(&text_lower) ||
        FALSE_POSITIVE_PATTERNS["python_syntax"].is_match(text) ||
        (FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(text) && 
         FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(text)) ||
        FALSE_POSITIVE_PATTERNS["corrupted_ocr"].is_match(text)
    }

    // Standard Luhn checksum used to validate plausible credit card numbers.
    fn luhn_check(card_number: &str) -> bool {
        let mut sum = 0;
        let mut double = false;

        for c in card_number.chars().rev() {
            if let Some(mut digit) = c.to_digit(10) {
                if double {
                    digit *= 2;
                    if digit > 9 {
                        digit -= 9;
                    }
                }
                sum += digit;
                double = !double;
            }
        }

        sum % 10 == 0
    }

    // Full-text scanning: applies all rules, filters duplicates, extracts contextual snippets, and returns violations.
    // pub fn check_text(&mut self, text: &str, context: &TextContext) -> Vec<Violation> {
    //     if text.trim().is_empty() {
    //         return Vec::new();
    //     }

    //     let text_lower = text.to_lowercase();
    //     if FALSE_POSITIVE_PATTERNS["lorem_ipsum"].is_match(&text_lower) ||
    //        FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(&text_lower) {
    //         return Vec::new();
    //     }

    //     if text.trim().len() < 10 {
    //         return Vec::new();
    //     }

    //     // Skip if it's mostly system content
    //     if FALSE_POSITIVE_PATTERNS["system_text"].is_match(text) ||
    //        FALSE_POSITIVE_PATTERNS["code_keywords"].is_match(text) ||
    //        FALSE_POSITIVE_PATTERNS["python_syntax"].is_match(text) {
    //         return Vec::new();
    //     }

    //     // Skip if both file paths and timestamps are present (likely system output)
    //     if FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(text) &&
    //        FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(text) {
    //         return Vec::new();
    //     }

    //     let mut violations = Vec::new();
    //     let mut seen = HashSet::new();

    //     for rule in &self.rules {
    //         for capture in rule.pattern.captures_iter(text) {
    //             if let Some(matched_text) = capture.get(0) {
    //                 let matched_str = matched_text.as_str();

    //                  for (rule, matched_str) in potential_matches {
    //                     // ✅ CHECK: Is this a recent duplicate?
    //                     if self.is_recent_duplicate(&rule.name, matched_str) {
    //                         continue; // Skip duplicate
    //                     }
    //                 }

    //                 let (is_valid, confidence, contextual_clues) = 
    //                     (rule.validator)(matched_str, text, context, &self.context_analyzer);
                    
    //                 if is_valid && confidence > 0.4 {
    //                     let normalized_text: String = matched_str
    //                         .chars()
    //                         .filter(|c| c.is_ascii_alphanumeric() || *c == '@' || *c == '.' || *c == '-')
    //                         .collect::<String>()
    //                         .to_lowercase();
                            
    //                     let violation_key = (rule.name.clone(), normalized_text);
    //                     if !seen.contains(&violation_key) {
    //                         seen.insert(violation_key);
                            
    //                         let surrounding_text = self.extract_surrounding_context(text, matched_str);
    //                         violations.push(Violation {
    //                             rule_type: rule.name.clone(),
    //                             confidence,
    //                             matched_text: matched_str.to_string(),
    //                             x: 0,
    //                             y: 0,
    //                             context_confidence: confidence,
    //                             surrounding_text,
    //                             contextual_clues,
    //                         });
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     violations
    // }

    // Full-text scanning: applies all rules, filters duplicates, extracts contextual snippets, and returns violations.
pub fn check_text(&mut self, text: &str, context: &TextContext) -> Vec<Violation> {
    if text.trim().is_empty() {
        return Vec::new();
    }

    let text_lower = text.to_lowercase();
    if FALSE_POSITIVE_PATTERNS["lorem_ipsum"].is_match(&text_lower) ||
       FALSE_POSITIVE_PATTERNS["documentation_keywords"].is_match(&text_lower) {
        return Vec::new();
    }

    if text.trim().len() < 10 {
        return Vec::new();
    }

    // Skip if it's mostly system content
    if FALSE_POSITIVE_PATTERNS["system_text"].is_match(text) ||
       FALSE_POSITIVE_PATTERNS["code_keywords"].is_match(text) ||
       FALSE_POSITIVE_PATTERNS["python_syntax"].is_match(text) {
        return Vec::new();
    }

    // Skip if both file paths and timestamps are present (likely system output)
    if FALSE_POSITIVE_PATTERNS["file_path_patterns"].is_match(text) &&
       FALSE_POSITIVE_PATTERNS["timestamp_patterns"].is_match(text) {
        return Vec::new();
    }

    let mut violations = Vec::new();
    let mut seen = HashSet::new();

    // --- PHASE 1: Collect all matches with rule names (not references) ---
    let mut potential_matches: Vec<(String, String)> = Vec::new(); // (rule_name, matched_text)
    
    for rule in &self.rules {
        for capture in rule.pattern.captures_iter(text) {
            if let Some(matched_text) = capture.get(0) {
                // Store rule name and matched text as owned strings
                potential_matches.push((rule.name.clone(), matched_text.as_str().to_string()));
            }
        }
    }

    // --- PHASE 2: Process matches ---
    for (rule_name, matched_str) in potential_matches {
        // ✅ CHECK: Is this a recent duplicate? (do this BEFORE accessing rules)
        if self.is_recent_duplicate(&rule_name, &matched_str) {
            continue; // Skip duplicate
        }

        // Now find the rule by name
        if let Some(rule) = self.rules.iter().find(|r| r.name == rule_name) {
            let (is_valid, confidence, contextual_clues) = 
                (rule.validator)(&matched_str, text, context, &self.context_analyzer);
            
            if is_valid && confidence > 0.4 {
                let normalized_text: String = matched_str
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '@' || *c == '.' || *c == '-')
                    .collect::<String>()
                    .to_lowercase();
                    
                let violation_key = (rule_name.clone(), normalized_text);
                if !seen.contains(&violation_key) {
                    seen.insert(violation_key.clone());
                    
                    let surrounding_text = self.extract_surrounding_context(text, &matched_str);
                    violations.push(Violation {
                        rule_type: rule_name,
                        confidence,
                        matched_text: matched_str,
                        x: 0,
                        y: 0,
                        context_confidence: confidence,
                        surrounding_text,
                        contextual_clues,
                    });
                }
            }
        }
    }

    violations
}

    // Extracts left/right neighboring text window for context scoring.
    fn extract_surrounding_context(&self, full_text: &str, target_text: &str) -> String {
        if let Some(index) = full_text.find(target_text) {
            let start = index.saturating_sub(50);
            let end = (index + target_text.len() + 50).min(full_text.len());
            full_text[start..end].to_string()
        } else {
            String::new()
        }
    }

    // Two-layer evaluation: full-text violations + per-word context validation using OCR positional metadata.
    pub fn check_ocr_data(&mut self, text: &str, ocr_data: &OcrData) -> (Vec<Violation>, Vec<Violation>) {
        let full_text_violations = self.check_text(text, &ocr_data.context);
        let mut seen_in_this_screenshot: HashSet<String>  = HashSet::new();

        let mut word_violations = Vec::new();
        for (i, word_data) in ocr_data.words.iter().enumerate() {
            let word = word_data.text.trim();
            if word.len() < 2 {
                continue;
            }

            // Skip words that are likely OCR artifacts
            if regex::Regex::new(r"^[Il1oO0|\\/]{3,}$").unwrap().is_match(word) {
                continue;
            }

            // Use word's surrounding context for better validation
            let context_text = if word_data.surrounding_context.is_empty() {
                let context_start = i.saturating_sub(2);
                let context_end = (i + 3).min(ocr_data.words.len());
                let context_words: Vec<&str> = ocr_data.words[context_start..context_end]
                    .iter()
                    .map(|wd| wd.text.trim())
                    .collect();
                context_words.join(" ")
            } else {
                word_data.surrounding_context.clone()
            };

            let violations = self.check_text(&context_text, &ocr_data.context);
            for violation in violations {
                if violation.confidence > 0.7 {
                    word_violations.push(Violation {
                        x: word_data.left,
                        y: word_data.top,
                        ..violation
                    });
                }
            }
        }

        (full_text_violations, word_violations)
    }
}