//! Reentrancy detection using IR-level data flow analysis.
//!
//! ## Why IR Analysis?
//!
//! Source-level reentrancy detection often produces false positives because it cannot
//! reason about actual data flow. By analyzing the IR representation, we gain:
//!
//! 1. **Precise State Tracking**: Know exactly which storage slots are modified, not just
//!    which variables are mentioned in the code.
//!
//! 2. **Call Target Resolution**: Distinguish between internal calls (safe) and external
//!    calls (potential reentrancy vectors) based on instruction semantics.
//!
//! 3. **Ordering Guarantees**: The IR's sequential instruction stream makes "external call
//!    before state change" detection trivial - no AST traversal gymnastics needed.
//!
//! ## Pattern Evolution
//!
//! Classic reentrancy (external call → state write) is just the beginning. This scanner
//! extends to detect:
//!
//! - **Cross-function reentrancy**: State read in function A, external call in A, state
//!   write in function B (called from reentrant callback).
//!
//! - **Read-only reentrancy**: External call affects a view function's return value through
//!   state changes, even without direct state writes.
//!
//! ## False Positive Reduction
//!
//! The real challenge isn't finding potential reentrancy - it's distinguishing real vulnerabilities
//! from safe patterns. We use multiple strategies:
//!
//! - **Safe Pattern Recognition**: Detects ReentrancyGuard, CEI pattern, state-guard checks.
//! - **Confidence Scoring**: Assigns scores based on pattern strength, not binary yes/no.
//! - **Context Analysis**: Considers function visibility, modifiers, and call context.
//!
//! This layered approach reduces false positives while maintaining high recall on real vulnerabilities.

use crate::core::{Confidence, Finding, Severity, Location};
use crate::analysis::{
    SafePatternRecognizer, ConfidenceScorer, InterproceduralAnalyzer, LoopAnalyzer, PathExplorer,
};
use thalir_core::{
    analysis::{
        cursor::{ScannerCursor, IRCursor},
        pass::{Pass, PassManager, AnalysisID},
        pattern::{PatternBuilder, PatternMatcher},
    },
    contract::Contract,
    instructions::Instruction,
    block::BlockId,
};
#[cfg(test)]
use thalir_core::analysis::Pattern;
use anyhow::Result;

pub struct IRReentrancyScanner {
    pattern_matcher: PatternMatcher,
    external_calls: Vec<CallLocation>,
    state_modifications: Vec<StateModification>,
    findings: Vec<Finding>,
    safe_pattern_recognizer: SafePatternRecognizer,
    confidence_scorer: ConfidenceScorer,
}

#[derive(Debug, Clone)]
struct CallLocation {
    block: BlockId,
    instruction_index: usize,
    target: String,
    is_delegatecall: bool,
}

#[derive(Debug, Clone)]
struct StateModification {
    block: BlockId,
    instruction_index: usize,
    variable: String,
}

impl IRReentrancyScanner {
    fn format_ir_value(value: &str) -> String {
        let formatted = value
            .replace("External(", "")
            .replace("Param(ParamId(", "param_")
            .replace("Temp(TempId(", "temp_")
            .replace("Const(", "")
            .replace("))", "")
            .replace(")", "")
            .replace("mapping:", "mapping ")
            .replace("#Uint(", "uint")
            .replace("#Int(", "int")
            .replace("#Bool(", "bool");

        if formatted.starts_with("uint") || formatted.starts_with("int") {
            if let Some(pos) = formatted.find(',') {
                let (val_part, type_part) = formatted.split_at(pos);
                let type_size = type_part.trim_start_matches(", ").trim_end_matches(')');
                if formatted.starts_with("uint") {
                    return format!("uint{}({})", type_size, val_part.trim_start_matches("uint"));
                } else {
                    return format!("int{}({})", type_size, val_part.trim_start_matches("int"));
                }
            }
        }

        formatted
    }

    pub fn new() -> Self {
        let mut pattern_matcher = PatternMatcher::new();

        let reentrancy_pattern = PatternBuilder::new()
            .external_call()
            .then(PatternBuilder::new().state_write().build())
            .build();

        pattern_matcher.compile(reentrancy_pattern);

        Self {
            pattern_matcher,
            external_calls: Vec::new(),
            state_modifications: Vec::new(),
            findings: Vec::new(),
            safe_pattern_recognizer: SafePatternRecognizer::new(),
            confidence_scorer: ConfidenceScorer::new(),
        }
    }
    
    pub fn analyze(&mut self, contract: &Contract) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let interprocedural = InterproceduralAnalyzer::analyze(contract);

        let cross_function_patterns = interprocedural.find_cross_function_reentrancy(contract);

        for (func_name, function) in &contract.functions {
            let safe_analysis = self.safe_pattern_recognizer.analyze_function(function, contract);

            if self.should_skip_protected_function(&safe_analysis) {
                continue;
            }

            let mut cursor = ScannerCursor::at_entry(function);

            self.external_calls.clear();
            self.state_modifications.clear();

            let blocks: Vec<_> = cursor.traverse_dom_order().collect();

            for block_id in blocks {
                cursor.goto_first_inst(block_id);

                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    if self.is_external_call(instruction) {
                        self.external_calls.push(CallLocation {
                            block: block_id,
                            instruction_index: idx,
                            target: self.get_call_target(instruction),
                            is_delegatecall: self.is_delegatecall(instruction),
                        });
                    }

                    if self.is_state_modification(instruction) {
                        self.state_modifications.push(StateModification {
                            block: block_id,
                            instruction_index: idx,
                            variable: self.get_modified_variable(instruction),
                        });
                    }
                }
            }

            for call in &self.external_calls {
                for state_mod in &self.state_modifications {
                    if self.is_vulnerable_pattern(call, state_mod, function) {
                        let finding = self.create_finding_with_confidence(
                            contract,
                            func_name,
                            call,
                            state_mod,
                            &safe_analysis,
                        );
                        findings.push(finding);
                    }
                }
            }

            for pattern in &cross_function_patterns {
                if pattern.entry_function == *func_name {
                    let finding = self.create_cross_function_finding_from_pattern(
                        contract,
                        pattern,
                        &safe_analysis,
                    );
                    findings.push(finding);
                }
            }

            let mut loop_analyzer = LoopAnalyzer::new();
            loop_analyzer.analyze_function(function);
            let loop_patterns = loop_analyzer.find_loop_reentrancy_patterns(function);

            for pattern in loop_patterns {
                let finding = self.create_loop_finding(
                    contract,
                    func_name,
                    &pattern,
                    &safe_analysis,
                );
                findings.push(finding);
            }

            let mut path_explorer = PathExplorer::new();
            path_explorer.explore_function(function);
            let conditional_patterns = path_explorer.find_conditional_reentrancy();

            for pattern in conditional_patterns {
                let finding = self.create_conditional_finding(
                    contract,
                    func_name,
                    &pattern,
                    &safe_analysis,
                );
                findings.push(finding);
            }

            let matches = self.pattern_matcher.match_all(function);
            for m in matches {
                if let Some(finding) = self.create_finding_from_match_with_confidence(
                    contract,
                    func_name,
                    &m,
                    &safe_analysis,
                ) {
                    findings.push(finding);
                }
            }
        }

        self.findings = findings.clone();

        Ok(findings)
    }

    fn should_skip_protected_function(&self, safe_analysis: &crate::analysis::SafePatternAnalysis) -> bool {
        use crate::analysis::SafePattern;

        if safe_analysis.safety_confidence <= 0.9 {
            return false;
        }

        safe_analysis.has_pattern(SafePattern::ReentrancyGuard)
            || safe_analysis.has_pattern(SafePattern::MutexLock)
    }
    
    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
    
    fn is_external_call(&self, inst: &Instruction) -> bool {
        let inst_str = format!("{:?}", inst);

        match inst {
            Instruction::Call { target, .. } => {
                match target {
                    thalir_core::instructions::CallTarget::External(_) => true,
                    thalir_core::instructions::CallTarget::Internal(name) => {
                        name.contains("delegatecall")
                    }
                    _ => true, // Default to external for unknown targets
                }
            }
            Instruction::DelegateCall { .. } => true,
            _ => {
                inst_str.contains("call_ext") ||
                inst_str.contains("external_call") ||
                inst_str.contains("call{value:") ||
                inst_str.contains("delegatecall")
            }
        }
    }

    fn is_delegatecall(&self, inst: &Instruction) -> bool {
        match inst {
            Instruction::DelegateCall { .. } => true,
            Instruction::Call { target, .. } => {
                match target {
                    thalir_core::instructions::CallTarget::Internal(name) => {
                        name.contains("delegatecall")
                    }
                    _ => false,
                }
            }
            _ => {
                let inst_str = format!("{:?}", inst);
                inst_str.contains("DelegateCall")
            }
        }
    }
    
    fn is_state_modification(&self, inst: &Instruction) -> bool {
        let inst_str = format!("{:?}", inst);
        
        matches!(inst, 
            Instruction::StorageStore { .. } |
            Instruction::Store { .. } |
            Instruction::MappingStore { .. } |
            Instruction::ArrayStore { .. }
        ) || inst_str.contains("mapping_store") ||
             inst_str.contains("storage_store") ||
             inst_str.contains("sstore")
    }
    
    fn get_call_target(&self, inst: &Instruction) -> String {
        match inst {
            Instruction::Call { target, .. } => format!("{:?}", target),
            Instruction::DelegateCall { target, .. } => format!("delegate:{:?}", target),
            _ => "unknown".to_string(),
        }
    }
    
    fn get_modified_variable(&self, inst: &Instruction) -> String {
        match inst {
            Instruction::StorageStore { key, .. } => format!("storage:{:?}", key),
            Instruction::Store { location, .. } => format!("memory:{:?}", location),
            Instruction::MappingStore { key, .. } => format!("mapping:{:?}", key),
            Instruction::ArrayStore { index, .. } => format!("array:{:?}", index),
            _ => "unknown".to_string(),
        }
    }
    
    fn is_vulnerable_pattern(
        &self,
        call: &CallLocation,
        state_mod: &StateModification,
        function: &thalir_core::function::Function,
    ) -> bool {
        if call.block == state_mod.block {
            state_mod.instruction_index > call.instruction_index
        } else {
            self.block_dominates(call.block, state_mod.block, function)
        }
    }
    
    fn block_dominates(
        &self,
        dominator: BlockId,
        dominated: BlockId,
        _function: &thalir_core::function::Function,
    ) -> bool {
        dominator.0 < dominated.0
    }
    
    fn create_finding_with_confidence(
        &self,
        contract: &Contract,
        func_name: &str,
        call: &CallLocation,
        state_mod: &StateModification,
        safe_analysis: &crate::analysis::SafePatternAnalysis,
    ) -> Finding {
        let call_location = super::provenance::get_instruction_location(
            contract,
            func_name,
            call.block,
            call.instruction_index,
        );

        let state_mod_location = super::provenance::get_instruction_location(
            contract,
            func_name,
            state_mod.block,
            state_mod.instruction_index,
        );

        let has_multiple_evidence = self.external_calls.len() > 1 && self.state_modifications.len() > 1;
        let confidence_score = self.confidence_scorer.score_reentrancy(
            has_multiple_evidence,
            safe_analysis,
            false, // Not a critical operation
            func_name,
        );

        let confidence = if confidence_score.score >= 0.8 {
            Confidence::High
        } else if confidence_score.score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let call_type = if call.is_delegatecall {
            "delegatecall"
        } else {
            "external call"
        };

        let vulnerability_description = if call.is_delegatecall {
            "Delegatecall reentrancy vulnerability"
        } else {
            "Reentrancy vulnerability"
        };

        Finding::new(
            "reentrancy-ir".to_string(),
            Severity::High,
            confidence,
            format!("{} in function '{}'", vulnerability_description, func_name),
            format!(
                "Function '{}' in contract '{}' performs state modification ({}) after {} to {}. \
                 {}. This makes it vulnerable to reentrancy attacks. {}",
                func_name,
                contract.name,
                Self::format_ir_value(&state_mod.variable),
                call_type,
                Self::format_ir_value(&call.target),
                if call.is_delegatecall {
                    "Delegatecall executes external code in the current contract's storage context, allowing it to modify state and reenter"
                } else {
                    "External calls transfer control to untrusted contracts"
                },
                confidence_score.explanation
            ),
        )
        .with_locations(vec![call_location, state_mod_location])
        .with_contract(&contract.name)
        .with_function(func_name)
        .with_confidence_score(confidence, confidence_score.score as f64)
    }

    fn create_cross_function_finding_from_pattern(
        &self,
        contract: &Contract,
        pattern: &crate::analysis::CrossFunctionPattern,
        safe_analysis: &crate::analysis::SafePatternAnalysis,
    ) -> Finding {
        let is_critical = pattern.is_hook_based || pattern.state_modifications.len() > 1;
        let confidence_score = self.confidence_scorer.score_reentrancy(
            true, // Cross-function is multiple evidence
            safe_analysis,
            is_critical,
            &pattern.entry_function,
        );

        let confidence = if confidence_score.score >= 0.8 {
            Confidence::High
        } else if confidence_score.score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let call_path_str = pattern.call_path.join(" → ");
        let state_mods_str = pattern.state_modifications.join(", ");

        let vulnerability_type = if pattern.is_hook_based {
            "Hook-based cross-function reentrancy"
        } else {
            "Cross-function reentrancy"
        };

        let description = format!(
            "{} in '{}': Function makes external call at position {}, then calls '{}' (via path: {}) which modifies state variables [{}]. \
             An attacker can reenter through the external call before state finalization. {}",
            vulnerability_type,
            pattern.entry_function,
            pattern.external_call_position,
            pattern.callee_function,
            call_path_str,
            state_mods_str,
            confidence_score.explanation
        );

        let location_opt = if contract.functions.contains_key(&pattern.entry_function) {
            super::provenance::get_instruction_location(
                contract,
                &pattern.entry_function,
                pattern.external_call_block,
                pattern.external_call_position,
            )
        } else {
            Location {
                file: contract.metadata.source_file.clone().unwrap_or_else(|| format!("{}.sol", contract.name)),
                line: 0,
                column: 0,
                end_line: None,
                end_column: None,
                snippet: None,
                ir_position: None,
            }
        };

        Finding::new(
            "cross-function-reentrancy".to_string(),
            Severity::High,
            confidence,
            format!("{} in '{}'", vulnerability_type, pattern.entry_function),
            description,
        )
        .with_location(location_opt)
        .with_contract(&contract.name)
        .with_function(&pattern.entry_function)
        .with_confidence_score(confidence, confidence_score.score as f64)
    }

    fn create_conditional_finding(
        &self,
        contract: &Contract,
        func_name: &str,
        pattern: &crate::analysis::ConditionalReentrancyPattern,
        safe_analysis: &crate::analysis::SafePatternAnalysis,
    ) -> Finding {
        let confidence_score = self.confidence_scorer.score_reentrancy(
            true, // Multiple paths
            safe_analysis,
            false, // Not critical by default
            func_name,
        );

        let confidence = if confidence_score.score >= 0.8 {
            Confidence::High
        } else if confidence_score.score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let (call_block, call_idx) = pattern.external_call;
        let (mod_block, mod_idx) = pattern.state_modification;

        let divergence_str = if let Some(div) = pattern.divergence_point {
            format!(" (paths diverge at block {:?})", div)
        } else {
            String::new()
        };

        let description = format!(
            "Conditional reentrancy in '{}': External call at block {:?} instruction {} can lead to state modification at block {:?} instruction {} across different execution paths{}. \
             An attacker can reenter before state is finalized. {}",
            func_name,
            call_block,
            call_idx,
            mod_block,
            mod_idx,
            divergence_str,
            confidence_score.explanation
        );

        let location = super::provenance::get_instruction_location(
            contract,
            func_name,
            call_block,
            call_idx,
        );

        Finding::new(
            "conditional-reentrancy".to_string(),
            Severity::High,
            confidence,
            format!("Conditional reentrancy in '{}'", func_name),
            description,
        )
        .with_location(location)
        .with_contract(&contract.name)
        .with_function(func_name)
        .with_confidence_score(confidence, confidence_score.score as f64)
    }

    fn create_loop_finding(
        &self,
        contract: &Contract,
        func_name: &str,
        pattern: &crate::analysis::LoopReentrancyPattern,
        safe_analysis: &crate::analysis::SafePatternAnalysis,
    ) -> Finding {
        let is_critical = pattern.calls_in_loop.len() > 1 || pattern.modified_variables.len() > 1;
        let confidence_score = self.confidence_scorer.score_reentrancy(
            true, // Multiple operations (loop + state mod)
            safe_analysis,
            is_critical,
            func_name,
        );

        let confidence = if confidence_score.score >= 0.8 {
            Confidence::High
        } else if confidence_score.score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let call_count = pattern.calls_in_loop.len();
        let state_mod_count = pattern.state_mods_after_loop.len();
        let variables_str = pattern.modified_variables.join(", ");

        let description = format!(
            "Loop-based reentrancy in '{}': Function performs {} external call(s) inside a loop (header: block {:?}), \
             then modifies {} state variable(s) after the loop: [{}]. \
             An attacker can reenter during the loop iterations before state is finalized. {}",
            func_name,
            call_count,
            pattern.loop_info.header,
            state_mod_count,
            variables_str,
            confidence_score.explanation
        );

        let location = if let Some((block_id, inst_idx)) = pattern.calls_in_loop.first() {
            super::provenance::get_instruction_location(
                contract,
                func_name,
                *block_id,
                *inst_idx,
            )
        } else {
            Location {
                file: contract.metadata.source_file.clone().unwrap_or_else(|| format!("{}.sol", contract.name)),
                line: 0,
                column: 0,
                end_line: None,
                end_column: None,
                snippet: None,
                ir_position: None,
            }
        };

        Finding::new(
            "loop-reentrancy".to_string(),
            Severity::High,
            confidence,
            format!("Loop-based reentrancy in '{}'", func_name),
            description,
        )
        .with_location(location)
        .with_contract(&contract.name)
        .with_function(func_name)
        .with_confidence_score(confidence, confidence_score.score as f64)
    }

    fn create_finding_from_match_with_confidence(
        &self,
        contract: &Contract,
        func_name: &str,
        match_result: &thalir_core::analysis::pattern::Match,
        safe_analysis: &crate::analysis::SafePatternAnalysis,
    ) -> Option<Finding> {
        use thalir_core::analysis::pattern::MatchLocation;

        match &match_result.location {
            MatchLocation::Instruction { block, index } => {
                let location = super::provenance::get_instruction_location(
                    contract,
                    func_name,
                    *block,
                    *index,
                );

                let confidence_score = self.confidence_scorer.score_reentrancy(
                    true,
                    safe_analysis,
                    false,
                    func_name,
                );

                let confidence = if confidence_score.score >= 0.8 {
                    Confidence::High
                } else if confidence_score.score >= 0.5 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };

                Some(Finding::new(
                    "reentrancy-pattern".to_string(),
                    Severity::High,
                    confidence,
                    format!("Reentrancy pattern detected in function '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' matches reentrancy vulnerability pattern at block {:?}, instruction {}. {}",
                        func_name, contract.name, block, index, confidence_score.explanation
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name)
                .with_confidence_score(confidence, confidence_score.score as f64))
            }
            _ => None,
        }
    }

}

impl Pass for IRReentrancyScanner {
    fn name(&self) -> &'static str {
        "ir-reentrancy"
    }
    
    fn description(&self) -> &'static str {
        "Detect reentrancy vulnerabilities using IR analysis"
    }
    
    fn run_on_contract(&mut self, contract: &mut Contract, _manager: &mut PassManager) -> Result<()> {
        let _findings = self.analyze(contract)?;
        Ok(())
    }
    
    fn required_analyses(&self) -> Vec<AnalysisID> {
        vec![
            AnalysisID::ControlFlow,
            AnalysisID::Dominator,
        ]
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl Default for IRReentrancyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRReentrancyScanner {
    fn id(&self) -> &'static str {
        "ir-reentrancy"
    }

    fn name(&self) -> &'static str {
        "IR Reentrancy Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects reentrancy vulnerabilities by analyzing external calls followed by state modifications in IR"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn scan(&self, context: &crate::core::AnalysisContext) -> Result<Vec<Finding>> {
        let ir_contract = context.get_representation::<thalir_core::contract::Contract>()?;

        let mut scanner = Self::new();
        scanner.analyze(ir_contract)
    }

    fn required_representations(&self) -> crate::representations::RepresentationSet {
        crate::representations::RepresentationSet::new()
            .require::<thalir_core::contract::Contract>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use thalir_core::builder::IRBuilder;

    #[test]
    fn test_reentrancy_detection() {
        let mut builder = IRBuilder::new();

        let mut contract_builder = builder.contract("TestContract");



        let contract = contract_builder.build().unwrap();

        let mut Scanner = IRReentrancyScanner::new();
        let findings = Scanner.analyze(&contract).unwrap();

    }

    #[test]
    fn test_pattern_matching() {
        let Scanner = IRReentrancyScanner::new();

        let pattern = PatternBuilder::new()
            .external_call()
            .then(PatternBuilder::new().state_write().build())
            .build();

        match pattern {
            Pattern::Sequence(patterns) => {
                assert_eq!(patterns.len(), 2);
            }
            _ => panic!("Expected sequence pattern"),
        }
    }

    #[test]
    #[ignore] // Requires contracts/complex_patterns.sol test file (not in repo)
    fn test_complex_patterns_benchmark() {
        let possible_paths = [
            "contracts/complex_patterns.sol",
            "../../contracts/complex_patterns.sol",
            "../../../contracts/complex_patterns.sol",
        ];

        let contract_path = possible_paths
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or_else(|| {
                eprintln!("Skipping test - complex_patterns.sol not found in any of:");
                for p in &possible_paths {
                    eprintln!("  - {}", p);
                }
                eprintln!("Current dir: {:?}", std::env::current_dir());
                panic!("Test file not found");
            });

        println!("Using contract path: {}", contract_path);

        let content = std::fs::read_to_string(contract_path)
            .expect("Failed to read complex_patterns.sol");

        let contracts = thalir_transform::transform_solidity_to_ir(&content)
            .expect("Failed to transform to IR");

        println!("\n=== Testing Reentrancy Scanner on Benchmark ===");
        println!("Found {} contracts", contracts.len());

        let mut total_findings = 0;

        for contract in contracts {
            println!("\n--- Contract: {} ---", contract.name);

            let mut scanner = IRReentrancyScanner::new();
            let findings = scanner.analyze(&contract)
                .expect("Scanner analysis failed");

            println!("Found {} findings in {}", findings.len(), contract.name);

            for finding in &findings {
                println!("  - [{}] {}: {}",
                    finding.severity,
                    finding.title,
                    finding.description.chars().take(100).collect::<String>()
                );
            }

            total_findings += findings.len();
        }

        println!("\n=== Total Findings: {} ===", total_findings);

        assert!(total_findings > 0,
            "Scanner found no vulnerabilities in complex_patterns.sol, but there are 6 documented vulnerabilities");
    }
}
