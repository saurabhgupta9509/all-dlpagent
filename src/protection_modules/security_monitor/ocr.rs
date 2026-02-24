// OCR processing pipeline: preprocess image, run Tesseract, extract structured words,
// evaluate textual context with lightweight NLP, and output enriched OCR metadata.
use leptess::{LepTess, Variable};
use image::DynamicImage;
use whatlang::Lang;
use unicode_segmentation::UnicodeSegmentation;
use crate::protection_modules::security_monitor::types::{OcrData, WordData, TextContext};

struct NlpContextAnalyzer {
    common_names: Vec<&'static str>,
    business_terms: Vec<&'static str>,
    technical_terms: Vec<&'static str>,
}

impl NlpContextAnalyzer {
    // Initialize context dictionaries for personal, business, and technical detection.
    fn new() -> Self {
        Self {
            common_names: vec![
                "john", "jane", "michael", "sarah", "david", "lisa", "robert", "maria",
                "william", "emma", "james", "olivia", "alex", "sophia"
            ],
            business_terms: vec![
                "invoice", "receipt", "statement", "bill", "payment", "account", "balance",
                "transaction", "refund", "customer", "client", "vendor", "supplier"
            ],
            technical_terms: vec![
                "api", "endpoint", "database", "server", "client", "protocol", "encryption",
                "authentication", "authorization", "firewall", "malware", "phishing"
            ],
        }
    }

    // Derives language, domain tags, readability metrics, and sentence structure from text.
    fn analyze_context(&self, text: &str) -> TextContext {
        let text_lower = text.to_lowercase();
        let lang = whatlang::detect(&text_lower).map(|info| info.lang()).unwrap_or(Lang::Eng);
        
        let mut context = TextContext {
            language: format!("{:?}", lang),
            is_financial: false,
            is_technical: false,
            is_personal: false,
            is_business: false,
            contains_names: false,
            sentence_count: 0,
            avg_sentence_length: 0.0,
            readability_score: 0.0,
        };

        // Check for financial context
        let financial_keywords = ["credit", "card", "account", "bank", "payment", "money", "transfer", "balance"];
        context.is_financial = financial_keywords.iter().any(|&kw| text_lower.contains(kw));

        // Check for business context
        context.is_business = self.business_terms.iter().any(|&term| text_lower.contains(term));

        // Check for technical context
        context.is_technical = self.technical_terms.iter().any(|&term| text_lower.contains(term));

        // Check for personal names
        context.contains_names = self.common_names.iter().any(|&name| text_lower.contains(name));

        // Analyze sentence structure
        let sentences: Vec<&str> = text.split(|c| c == '.' || c == '!' || c == '?').collect();
        context.sentence_count = sentences.len();
        
        if !sentences.is_empty() {
            let total_chars: usize = sentences.iter().map(|s| s.chars().count()).sum();
            context.avg_sentence_length = total_chars as f32 / sentences.len() as f32;
        }

        // Simple readability score (higher = more complex)
        context.readability_score = self.calculate_readability(text);

        context
    }

    // Computes approximate Flesch Reading Ease score using word/sentence/syllable counts.
    fn calculate_readability(&self, text: &str) -> f32 {
        let words: Vec<&str> = text.split_whitespace().collect();
        let word_count = words.len();
        if word_count == 0 {
            return 0.0;
        }

        let sentence_count = text.split(|c| c == '.' || c == '!' || c == '?').count().max(1);
        let syllable_count = words.iter().map(|word| self.count_syllables(word)).sum::<usize>();

        // Flesch Reading Ease approximation
        let words_per_sentence = word_count as f32 / sentence_count as f32;
        let syllables_per_word = syllable_count as f32 / word_count as f32;

        206.835 - (1.015 * words_per_sentence) - (84.6 * syllables_per_word)
    }

    // Basic syllable estimator for readability scoring.
    fn count_syllables(&self, word: &str) -> usize {
        let word_lower = word.to_lowercase();
        let vowels = ['a', 'e', 'i', 'o', 'u', 'y'];
        let mut count = 0;
        let mut prev_char_vowel = false;

        for ch in word_lower.chars() {
            if vowels.contains(&ch) {
                if !prev_char_vowel {
                    count += 1;
                }
                prev_char_vowel = true;
            } else {
                prev_char_vowel = false;
            }
        }

        // Adjust for words ending with 'e'
        if word_lower.ends_with('e') && count > 1 {
            count -= 1;
        }

        count.max(1)
    }
}

pub struct OcrProcessor {
    tess: LepTess,
    nlp_context: NlpContextAnalyzer,
}

impl OcrProcessor {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Ensure Tesseract knows where to look for tessdata
        if std::env::var("TESSDATA_PREFIX").is_err() {
            std::env::set_var("TESSDATA_PREFIX", ".");
        }

        // let mut tess = LepTess::new(None, "eng")?;
        let mut tess = LepTess::new(None, "eng")
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        tess.set_variable(Variable::TesseditPagesegMode, "6")?;
        tess.set_variable(Variable::TesseditOcrEngineMode, "1")?;
        tess.set_variable(Variable::ClassifyEnableLearning, "0")?;
        tess.set_variable(Variable::TesseditCharWhitelist, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/.-_@!?&%$#*+()[]{}<>;,'\" ")?;
        tess.set_variable(Variable::PreserveInterwordSpaces, "1")?;
        tess.set_variable(Variable::UserDefinedDpi, "200")?;
        
        Ok(Self {
            tess,
            nlp_context: NlpContextAnalyzer::new(),
        })
    }

    // Full OCR routine: preprocess → Tesseract extraction → word segmentation → context analysis.
    pub fn extract_text(&mut self, image: &DynamicImage) -> Result<OcrData, Box<dyn std::error::Error>> {
        let processed_image = self.preprocess_for_ocr(image);
        
        let mut bytes: Vec<u8> = Vec::new();
        processed_image.write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png)?;
        
        self.tess.set_image_from_mem(&bytes)?;
        
        let text = self.tess.get_utf8_text()?;
        let words = self.extract_words_with_context(&text);
        let context = self.nlp_context.analyze_context(&text);
        
        println!("📝 Enhanced OCR analysis:");
        println!("   Language: {}", context.language);
        println!("   Context: Financial: {}, Business: {}, Technical: {}", 
                 context.is_financial, context.is_business, context.is_technical);
        println!("   Readability: {:.1}", context.readability_score);
        println!("   Sentences: {}", context.sentence_count);

        Ok(OcrData {
            text: self.post_process_text(&text),
            words,
            context,
        })
    }

    // Local-contrast enhancement backend used to improve OCR clarity on varied backgrounds.
    fn preprocess_for_ocr(&self, image: &DynamicImage) -> DynamicImage {
        let gray_img = image.to_luma8();
        let mut processed = image::ImageBuffer::new(gray_img.width(), gray_img.height());
        
        // Adaptive contrast enhancement
        for (x, y, pixel) in gray_img.enumerate_pixels() {
            let value = pixel[0];
            let enhanced_value = self.adaptive_contrast_enhancement(value, x, y, &gray_img);
            processed.put_pixel(x, y, image::Luma([enhanced_value]));
        }
        
        DynamicImage::ImageLuma8(processed)
    }

    // Performs neighborhood-based contrast boosting using a small sliding window.
    fn adaptive_contrast_enhancement(&self, value: u8, x: u32, y: u32, image: &image::GrayImage) -> u8 {
        // Simple local contrast enhancement
        let window_size = 5;
        let half_window = window_size / 2;
        let mut window_values = Vec::new();
        
        for i in 0..window_size {
            for j in 0..window_size {
                let nx = x as i32 + (i as i32 - half_window as i32);
                let ny = y as i32 + (j as i32 - half_window as i32);
                
                if nx >= 0 && nx < image.width() as i32 && ny >= 0 && ny < image.height() as i32 {
                    if let Some(pixel) = image.get_pixel_checked(nx as u32, ny as u32) {
                        window_values.push(pixel[0]);
                    }
                }
            }
        }
        
        if window_values.is_empty() {
            return value;
        }
        
        let min_val = *window_values.iter().min().unwrap();
        let max_val = *window_values.iter().max().unwrap();
        let range = max_val - min_val;
        
        if range > 10 {
            // Enhance contrast in high-variability regions
            if value < 128 {
                value.saturating_sub(25).max(0)
            } else {
                value.saturating_add(25).min(255)
            }
        } else {
            // Preserve low-variability regions (likely backgrounds)
            value
        }
    }

    // Produces word list with bounding box approximations, confidence scores, and local context window.
    fn extract_words_with_context(&self, text: &str) -> Vec<WordData> {
        let mut words = Vec::new();
        let mut x = 0;
        
        // Use unicode-aware segmentation for better word boundaries
        for word in text.unicode_words() {
            let trimmed = word.trim();
            if !trimmed.is_empty() && self.is_valid_word(trimmed) {
                let word_length = self.calculate_visual_length(trimmed);
                
                words.push(WordData {
                    text: trimmed.to_string(),
                    left: x,
                    top: 0,
                    width: (word_length * 8) as i32,
                    height: 16,
                    confidence: self.calculate_word_confidence(trimmed),
                    surrounding_context: self.extract_surrounding_context(text, trimmed),
                });
                
                x += (word_length * 10) as i32;
            }
        }
        
        words
    }

    // Filters OCR artifacts and noisy tokens using regex heuristics.
    fn is_valid_word(&self, word: &str) -> bool {
        if word.len() < 2 {
            return false;
        }
        
        // Filter out common OCR artifacts
        let artifact_patterns = [
            r"^[Il1oO0|\\/]{3,}$",  // Repeated similar characters
            r"^[^A-Za-z0-9]{3,}$",   // Mostly non-alphanumeric
            r"^[A-Za-z]{1,2}$",      // Very short alphabetic
        ];
        
        for pattern in &artifact_patterns {
            if regex::Regex::new(pattern).unwrap().is_match(word) {
                return false;
            }
        }
        
        true
    }

    // Approximates on-screen word width using character class weighting.
    fn calculate_visual_length(&self, word: &str) -> usize {
        // Account for character width variations
        let wide_chars = ['M', 'W', 'm', 'w'];
        let narrow_chars = ['i', 'l', '1', 'I', 't', 'f', 'r'];
        
        let mut length = 0;
        for ch in word.chars() {
            if wide_chars.contains(&ch) {
                length += 2;
            } else if narrow_chars.contains(&ch) {
                length += 1;
            } else {
                length += 1;
            }
        }
        
        length
    }

    // Computes heuristic confidence penalty for ambiguous characters; slightly boosts clean tokens.
    fn calculate_word_confidence(&self, word: &str) -> f32 {
        let mut confidence = 1.0;
        
        // Reduce confidence for words with ambiguous characters
        let ambiguous_chars = ['0', 'O', '1', 'I', 'l', '5', 'S', '8', 'B'];
        let ambiguous_count = word.chars().filter(|c| ambiguous_chars.contains(c)).count();
        
        if ambiguous_count > 0 {
            confidence -= (ambiguous_count as f32 / word.len() as f32) * 0.3;
        }
        
        // Increase confidence for dictionary-like words
        if word.chars().all(|c| c.is_alphabetic()) && word.len() > 3 {
            confidence += 0.1;
        }
        
        confidence.max(0.1).min(1.0)
    }

    // Extracts neighboring words to give each token contextual semantic hints.
    fn extract_surrounding_context(&self, full_text: &str, target_word: &str) -> String {
        let words: Vec<&str> = full_text.split_whitespace().collect();
        if let Some(pos) = words.iter().position(|&w| w == target_word) {
            let start = pos.saturating_sub(3);
            let end = (pos + 4).min(words.len());
            words[start..end].join(" ")
        } else {
            String::new()
        }
    }

    // Normalizes spacing and applies final text cleanup after OCR extraction.
    fn post_process_text(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        
        let mut processed = text.to_string();
        
        // Normalize whitespace
        processed = regex::Regex::new(r"\s+")
            .unwrap()
            .replace_all(&processed, " ")
            .trim()
            .to_string();
        
        // Fix common OCR errors
        processed = self.correct_common_ocr_errors(&processed);
        
        processed
    }

    // Fixes recurring OCR substitution patterns (rn→m, vv→w, etc.).
    fn correct_common_ocr_errors(&self, text: &str) -> String {
        let corrections = [
            (r"(?i)rn\b", "m"),      // 'rn' -> 'm'
            (r"(?i)cl\b", "d"),      // 'cl' -> 'd'
            (r"(?i)vv", "w"),        // 'vv' -> 'w'
            (r"(?i)l\b", "1"),       // 'l' at end -> '1'
            (r"(?i)\|", "I"),        // '|' -> 'I'
        ];
        
        let mut result = text.to_string();
        for (pattern, replacement) in &corrections {
            result = regex::Regex::new(pattern).unwrap().replace_all(&result, *replacement).to_string();
        }
        
        result
    }
}