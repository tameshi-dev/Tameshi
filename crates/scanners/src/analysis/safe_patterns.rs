//! Safe Pattern Recognizer
//!
//! Identifies common safe patterns that reduce false positives:
//! - ReentrancyGuard modifier
//! - Checks-Effects-Interactions (CEI) pattern
//! - OpenZeppelin Ownable pattern
//! - SafeERC20 library usage
//! - Initialization guards (initialized, initializer)

use thalir_core::{
    contract::Contract,
    function::Function,
    instructions::Instruction,
    block::BlockId,
};
use std::collections::{HashSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafePattern {
    ReentrancyGuard,
    ChecksEffectsInteractions,
    OwnablePattern,
    SafeERC20,
    InitializationGuard,
    PullPayment,
    MutexLock,
}

#[derive(Debug, Clone)]
pub struct SafePatternAnalysis {
    pub patterns: HashSet<SafePattern>,
    pub safety_confidence: f32,
    pub evidence: HashMap<SafePattern, String>,
}

impl SafePatternAnalysis {
    pub fn has_pattern(&self, pattern: SafePattern) -> bool {
        self.patterns.contains(&pattern)
    }

    pub fn has_reentrancy_protection(&self) -> bool {
        self.has_pattern(SafePattern::ReentrancyGuard) ||
        self.has_pattern(SafePattern::ChecksEffectsInteractions) ||
        self.has_pattern(SafePattern::MutexLock)
    }

    pub fn has_access_control(&self) -> bool {
        self.has_pattern(SafePattern::OwnablePattern)
    }
}

pub struct SafePatternRecognizer {
    safe_modifiers: HashSet<String>,
    safe_libraries: HashSet<String>,
}

impl SafePatternRecognizer {
    pub fn new() -> Self {
        let mut safe_modifiers = HashSet::new();

        safe_modifiers.insert("nonReentrant".to_string());
        safe_modifiers.insert("nonreentrant".to_string());
        safe_modifiers.insert("reentrancyGuard".to_string());
        safe_modifiers.insert("noReentrancy".to_string());
        safe_modifiers.insert("locked".to_string());

        safe_modifiers.insert("onlyOwner".to_string());
        safe_modifiers.insert("onlyAdmin".to_string());
        safe_modifiers.insert("onlyGovernance".to_string());
        safe_modifiers.insert("onlyAuthorized".to_string());
        safe_modifiers.insert("onlyRole".to_string());

        safe_modifiers.insert("initializer".to_string());
        safe_modifiers.insert("onlyUninitialized".to_string());
        safe_modifiers.insert("onlyInitializing".to_string());

        let mut safe_libraries = HashSet::new();
        safe_libraries.insert("SafeERC20".to_string());
        safe_libraries.insert("SafeMath".to_string());
        safe_libraries.insert("Address".to_string());

        Self {
            safe_modifiers,
            safe_libraries,
        }
    }

    pub fn analyze_function(&self, function: &Function, contract: &Contract) -> SafePatternAnalysis {
        let mut patterns = HashSet::new();
        let mut evidence = HashMap::new();

        if let Some(pattern) = self.check_reentrancy_guard(function) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function has nonReentrant modifier".to_string());
        }

        if let Some(pattern) = self.check_cei_pattern(function) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function follows CEI pattern (no state changes after external calls)".to_string());
        }

        if let Some(pattern) = self.check_ownable_pattern(function, contract) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function uses Ownable access control".to_string());
        }

        if let Some(pattern) = self.check_safe_erc20(function) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function uses SafeERC20 library".to_string());
        }

        if let Some(pattern) = self.check_initialization_guard(function) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function has initialization guard".to_string());
        }

        if let Some(pattern) = self.check_mutex_pattern(function) {
            patterns.insert(pattern);
            evidence.insert(pattern, "Function uses mutex/lock pattern".to_string());
        }

        let safety_confidence = self.calculate_safety_confidence(&patterns);

        SafePatternAnalysis {
            patterns,
            safety_confidence,
            evidence,
        }
    }

    fn check_reentrancy_guard(&self, function: &Function) -> Option<SafePattern> {
        for modifier in &function.modifiers {
            let modifier_str = format!("{:?}", modifier).to_lowercase();
            for safe_mod in &self.safe_modifiers {
                if modifier_str.contains(&safe_mod.to_lowercase()) &&
                   (safe_mod.to_lowercase().contains("reentrant") ||
                    safe_mod.to_lowercase().contains("locked")) {
                    return Some(SafePattern::ReentrancyGuard);
                }
            }
        }

        let mut has_lock_set = false;
        let mut has_lock_clear = false;

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::StorageStore { key, value, .. } = instruction {
                    let key_str = format!("{:?}", key).to_lowercase();
                    let value_str = format!("{:?}", value);

                    if key_str.contains("locked") || key_str.contains("_status") || key_str.contains("_guard") {
                        if value_str.contains("true") || value_str.contains("1") {
                            has_lock_set = true;
                        }
                        if value_str.contains("false") || value_str.contains("0") {
                            has_lock_clear = true;
                        }
                    }
                }
            }
        }

        if has_lock_set && has_lock_clear {
            return Some(SafePattern::ReentrancyGuard);
        }

        None
    }

    fn check_cei_pattern(&self, function: &Function) -> Option<SafePattern> {
        let mut first_external_call_block: Option<BlockId> = None;
        let mut state_mods_after_call = false;

        for (block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if self.is_external_call(instruction) {
                    if first_external_call_block.is_none() {
                        first_external_call_block = Some(*block_id);
                    }
                }

                if self.is_state_modification(instruction) {
                    if first_external_call_block.is_some() {
                        state_mods_after_call = true;
                    }
                }
            }
        }

        if first_external_call_block.is_some() && !state_mods_after_call {
            return Some(SafePattern::ChecksEffectsInteractions);
        }

        None
    }

    fn check_ownable_pattern(&self, function: &Function, _contract: &Contract) -> Option<SafePattern> {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::Require { condition, message } = instruction {
                    let message_lower = message.to_lowercase();
                    let condition_str = format!("{:?}", condition).to_lowercase();

                    if message_lower.contains("ownable") ||
                       message_lower.contains("onlyowner") ||
                       message_lower.contains("only owner") ||
                       condition_str.contains("owner") {
                        return Some(SafePattern::OwnablePattern);
                    }
                }

                if let Instruction::Require { condition, .. } = instruction {
                    if self.checks_msg_sender_against_storage(condition, function) {
                        return Some(SafePattern::OwnablePattern);
                    }
                }
            }
        }

        for modifier in &function.modifiers {
            let modifier_str = format!("{:?}", modifier).to_lowercase();
            if modifier_str.contains("onlyowner") || modifier_str.contains("ownable") {
                return Some(SafePattern::OwnablePattern);
            }
        }

        None
    }

    fn check_safe_erc20(&self, function: &Function) -> Option<SafePattern> {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::Call { target, .. } = instruction {
                    let target_str = format!("{:?}", target);
                    if target_str.contains("SafeERC20") ||
                       target_str.contains("safeTransfer") ||
                       target_str.contains("safeTransferFrom") ||
                       target_str.contains("safeApprove") {
                        return Some(SafePattern::SafeERC20);
                    }
                }
            }
        }

        None
    }

    fn check_initialization_guard(&self, function: &Function) -> Option<SafePattern> {
        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::Require { message, .. } = instruction {
                    let message_lower = message.to_lowercase();
                    if message_lower.contains("initialized") ||
                       message_lower.contains("initializing") ||
                       message_lower.contains("initializer") {
                        return Some(SafePattern::InitializationGuard);
                    }
                }

                if let Instruction::StorageLoad { key, .. } = instruction {
                    let key_str = format!("{:?}", key).to_lowercase();
                    if key_str.contains("initialized") || key_str.contains("_init") {
                        return Some(SafePattern::InitializationGuard);
                    }
                }
            }
        }

        for modifier in &function.modifiers {
            let modifier_str = format!("{:?}", modifier).to_lowercase();
            if modifier_str.contains("initializer") || modifier_str.contains("reinitializer") {
                return Some(SafePattern::InitializationGuard);
            }
        }

        None
    }

    fn check_mutex_pattern(&self, function: &Function) -> Option<SafePattern> {
        let mut mutex_vars = Vec::new();

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::StorageStore { key, .. } = instruction {
                    let key_str = format!("{:?}", key).to_lowercase();
                    if key_str.contains("mutex") || key_str.contains("lock") {
                        mutex_vars.push(key_str);
                    }
                }
            }
        }

        if !mutex_vars.is_empty() {
            return Some(SafePattern::MutexLock);
        }

        None
    }

    fn is_external_call(&self, inst: &Instruction) -> bool {
        match inst {
            Instruction::Call { target, .. } => {
                matches!(target, thalir_core::instructions::CallTarget::External(_))
            }
            Instruction::DelegateCall { .. } => true,
            _ => false,
        }
    }

    fn is_state_modification(&self, inst: &Instruction) -> bool {
        matches!(inst,
            Instruction::StorageStore { .. } |
            Instruction::MappingStore { .. } |
            Instruction::ArrayStore { .. }
        )
    }

    fn checks_msg_sender_against_storage(&self, _condition: &thalir_core::values::Value, _function: &Function) -> bool {
        false
    }

    fn calculate_safety_confidence(&self, patterns: &HashSet<SafePattern>) -> f32 {
        if patterns.is_empty() {
            return 0.0;
        }

        let mut confidence: f32 = 0.0;

        for pattern in patterns {
            confidence += match pattern {
                SafePattern::ReentrancyGuard => 0.9,  // Very high confidence
                SafePattern::ChecksEffectsInteractions => 0.85,
                SafePattern::OwnablePattern => 0.8,
                SafePattern::SafeERC20 => 0.75,
                SafePattern::InitializationGuard => 0.7,
                SafePattern::PullPayment => 0.8,
                SafePattern::MutexLock => 0.9,
            };
        }

        confidence.min(1.0)
    }
}

impl Default for SafePatternRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_pattern_recognition() {
        let recognizer = SafePatternRecognizer::new();

        assert!(recognizer.safe_modifiers.contains("nonReentrant"));
        assert!(recognizer.safe_modifiers.contains("onlyOwner"));
        assert!(recognizer.safe_modifiers.contains("initializer"));
    }

    #[test]
    fn test_safety_confidence_calculation() {
        let recognizer = SafePatternRecognizer::new();

        let mut patterns = HashSet::new();
        patterns.insert(SafePattern::ReentrancyGuard);

        let confidence = recognizer.calculate_safety_confidence(&patterns);
        assert!(confidence >= 0.9);
        assert!(confidence <= 1.0);
    }
}
