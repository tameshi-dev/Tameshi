//! Time-based vulnerability Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use anyhow::Result;
use std::collections::HashMap;
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{AnalysisID, Pass, PassManager},
    },
    contract::Contract,
    instructions::{ContextVariable, Instruction},
};

pub struct IRTimeVulnerabilityScanner {
    findings: Vec<Finding>,
}

impl IRTimeVulnerabilityScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn get_findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }

    pub fn analyze(&mut self, contract: &Contract) -> Result<Vec<Finding>> {
        self.findings.clear();

        for (func_name, function) in &contract.functions {
            let mut cursor = ScannerCursor::at_entry(function);
            let mut time_dependencies = Vec::new();
            let mut block_dependencies = Vec::new();
            let mut control_flow_usage = HashMap::new();
            let mut arithmetic_usage = HashMap::new();

            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::GetContext { result, var } => match var {
                            ContextVariable::BlockTimestamp => {
                                time_dependencies.push((block_id, idx, result, "block.timestamp"));
                            }
                            ContextVariable::BlockNumber => {
                                block_dependencies.push((block_id, idx, result, "block.number"));
                            }
                            ContextVariable::BlockDifficulty => {
                                block_dependencies.push((
                                    block_id,
                                    idx,
                                    result,
                                    "block.difficulty",
                                ));
                            }
                            _ => {}
                        },

                        Instruction::Require { condition, message } => {
                            if self.uses_time_value(
                                condition,
                                &time_dependencies,
                                &block_dependencies,
                            ) {
                                control_flow_usage
                                    .insert((block_id, idx), ("require", message.as_str()));
                            }
                        }

                        Instruction::Add {
                            result,
                            left,
                            right,
                            ..
                        }
                        | Instruction::Sub {
                            result,
                            left,
                            right,
                            ..
                        }
                        | Instruction::Mul {
                            result,
                            left,
                            right,
                            ..
                        }
                        | Instruction::Div {
                            result,
                            left,
                            right,
                            ..
                        } => {
                            if self.value_depends_on_time(
                                left,
                                &time_dependencies,
                                &block_dependencies,
                            ) || self.value_depends_on_time(
                                right,
                                &time_dependencies,
                                &block_dependencies,
                            ) {
                                arithmetic_usage.insert((block_id, idx), result);
                            }
                        }

                        Instruction::Lt {
                            result,
                            left,
                            right,
                        }
                        | Instruction::Gt {
                            result,
                            left,
                            right,
                        }
                        | Instruction::Le {
                            result,
                            left,
                            right,
                        }
                        | Instruction::Ge {
                            result,
                            left,
                            right,
                        }
                        | Instruction::Eq {
                            result,
                            left,
                            right,
                        }
                        | Instruction::Ne {
                            result,
                            left,
                            right,
                        } => {
                            if self.value_depends_on_time(
                                left,
                                &time_dependencies,
                                &block_dependencies,
                            ) || self.value_depends_on_time(
                                right,
                                &time_dependencies,
                                &block_dependencies,
                            ) {
                                control_flow_usage.insert(
                                    (block_id, idx),
                                    ("comparison", "time-based comparison"),
                                );
                            }
                        }

                        _ => {}
                    }
                }
            }

            self.analyze_timestamp_dependence(
                contract,
                func_name,
                &time_dependencies,
                &control_flow_usage,
            );
            self.analyze_block_manipulation(
                contract,
                func_name,
                &block_dependencies,
                &control_flow_usage,
            );
            self.analyze_time_arithmetic(
                contract,
                func_name,
                &arithmetic_usage,
                &time_dependencies,
            );
            self.analyze_short_timeframes(contract, func_name, function, &time_dependencies);
        }

        Ok(self.findings.clone())
    }

    fn uses_time_value(
        &self,
        condition: &thalir_core::values::Value,
        time_deps: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
        block_deps: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
    ) -> bool {
        for (_, _, time_val, _) in time_deps.iter().chain(block_deps.iter()) {
            if std::ptr::eq(condition, *time_val) {
                return true;
            }
        }
        false
    }

    fn value_depends_on_time(
        &self,
        value: &thalir_core::values::Value,
        time_deps: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
        block_deps: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
    ) -> bool {
        for (_, _, time_val, _) in time_deps.iter().chain(block_deps.iter()) {
            if std::ptr::eq(value, *time_val) {
                return true;
            }
        }
        false
    }

    fn analyze_timestamp_dependence(
        &mut self,
        contract: &Contract,
        func_name: &str,
        time_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
        control_flow_usage: &HashMap<(thalir_core::block::BlockId, usize), (&str, &str)>,
    ) {
        if time_dependencies.is_empty() {
            return;
        }

        let func_lower = func_name.to_lowercase();
        let is_randomness_related = func_lower.contains("random")
            || func_lower.contains("lottery")
            || func_lower.contains("winner")
            || func_lower.contains("shuffle");

        let mut has_suspicious_access_control = false;
        for ((_, _), (usage_type, context)) in control_flow_usage {
            if *usage_type == "require" {
                let ctx_lower = context.to_lowercase();
                if ctx_lower.contains("deadline")
                    || ctx_lower.contains("expire")
                    || ctx_lower.contains("timeout")
                    || ctx_lower.contains("cooldown")
                    || ctx_lower.contains("vesting")
                    || ctx_lower.contains("lock")
                    || ctx_lower.contains("delay")
                    || ctx_lower.contains("period")
                {
                    continue;
                }

                if ctx_lower.contains("owner")
                    || ctx_lower.contains("admin")
                    || ctx_lower.contains("authorized")
                    || ctx_lower.contains("allowed")
                {
                    has_suspicious_access_control = true;
                }
            }
        }

        if is_randomness_related {
            if let Some((block_id, idx, _, _)) = time_dependencies.first() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "timestamp-randomness".to_string(),
                    Severity::High,
                    Confidence::High,
                    format!("Timestamp used for randomness in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' appears to use block.timestamp for randomness generation. This is highly predictable and manipulable by miners. Use a verifiable random function (VRF) instead",
                        func_name, contract.name
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        } else if has_suspicious_access_control {
            if let Some((block_id, idx, _, _)) = time_dependencies.first() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "timestamp-access-control".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Timestamp-based access control in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' uses block.timestamp for access control logic. This can be manipulated by miners within ~15 second tolerance",
                        func_name, contract.name
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }

    fn analyze_block_manipulation(
        &mut self,
        contract: &Contract,
        func_name: &str,
        block_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
        _control_flow_usage: &HashMap<(thalir_core::block::BlockId, usize), (&str, &str)>,
    ) {
        if block_dependencies.is_empty() {
            return;
        }

        let func_lower = func_name.to_lowercase();
        let is_randomness_related = func_lower.contains("random")
            || func_lower.contains("lottery")
            || func_lower.contains("winner")
            || func_lower.contains("shuffle");

        for (block_id, idx, _, block_property) in block_dependencies {
            match *block_property {
                "block.difficulty" => {
                    let location = super::provenance::get_instruction_location(
                        contract, func_name, *block_id, *idx,
                    );

                    self.findings.push(Finding::new(
                        "block-difficulty-usage".to_string(),
                        Severity::High,
                        Confidence::High,
                        format!("Deprecated block.difficulty in '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' uses block.difficulty which is deprecated and unreliable. Use Chainlink VRF for randomness",
                            func_name, contract.name
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name));
                }
                "block.number" => {
                    if is_randomness_related {
                        let location = super::provenance::get_instruction_location(
                            contract, func_name, *block_id, *idx,
                        );

                        self.findings.push(Finding::new(
                            "block-number-randomness".to_string(),
                            Severity::Medium,
                            Confidence::High,
                            format!("Block number used for randomness in '{}'", func_name),
                            format!(
                                "Function '{}' in contract '{}' appears to use block.number for randomness. Block number is predictable and should not be used for random number generation",
                                func_name, contract.name
                            ),
                        )
                        .with_location(location)
                        .with_contract(&contract.name)
                        .with_function(func_name));
                    }
                }
                _ => {}
            }
        }
    }

    fn analyze_time_arithmetic(
        &mut self,
        contract: &Contract,
        func_name: &str,
        arithmetic_usage: &HashMap<
            (thalir_core::block::BlockId, usize),
            &thalir_core::values::Value,
        >,
        time_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
    ) {
        if arithmetic_usage.is_empty() || time_dependencies.is_empty() {
            return;
        }

        let arithmetic_count = arithmetic_usage.len();

        if arithmetic_count > 2 {
            if let Some(((block_id, idx), _)) = arithmetic_usage.iter().next() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "complex-time-arithmetic".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Complex time arithmetic in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' performs {} arithmetic operations on time values. Complex time calculations increase the attack surface for timestamp manipulation",
                        func_name, contract.name, arithmetic_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }

    fn analyze_short_timeframes(
        &mut self,
        contract: &Contract,
        func_name: &str,
        function: &thalir_core::function::Function,
        time_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
    ) {
        if time_dependencies.is_empty() {
            return;
        }

        let mut short_timeframe_constants = Vec::new();

        for (_block_id, block) in &function.body.blocks {
            for instruction in &block.instructions {
                if let Instruction::Lt { left, right, .. }
                | Instruction::Gt { left, right, .. }
                | Instruction::Le { left, right, .. }
                | Instruction::Ge { left, right, .. } = instruction
                {
                    if let thalir_core::values::Value::Constant(
                        thalir_core::values::Constant::Uint(value, _),
                    ) = right
                    {
                        let value_str = value.to_string();
                        if let Ok(val_u64) = value_str.parse::<u64>() {
                            if val_u64 < 3600 && val_u64 > 0 {
                                short_timeframe_constants.push(value.clone());
                            }
                        }
                    }
                }
            }
        }

        if !short_timeframe_constants.is_empty() {
            if let Some((block_id, idx, _, _)) = time_dependencies.first() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "short-timeframe-dependence".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Short timeframe dependence in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' uses timestamp comparisons with short timeframes (found {} small constants). Short timeframes are more vulnerable to miner manipulation",
                        func_name, contract.name, short_timeframe_constants.len()
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }

    fn analyze_any_time_usage(
        &mut self,
        contract: &Contract,
        func_name: &str,
        time_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
        block_dependencies: &[(
            thalir_core::block::BlockId,
            usize,
            &thalir_core::values::Value,
            &str,
        )],
    ) {
        if !time_dependencies.is_empty() {
            for (block_id, idx, _, context_var) in time_dependencies {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "timestamp-usage".to_string(),
                    Severity::Medium,
                    Confidence::High,
                    format!("Timestamp usage detected in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' uses {} which can be manipulated by miners within ~15 second tolerance",
                        func_name, contract.name, context_var
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }

        if !block_dependencies.is_empty() {
            for (block_id, idx, _, context_var) in block_dependencies {
                let (severity, description) = match *context_var {
                    "block.difficulty" => (
                        Severity::High,
                        "Block difficulty is deprecated and should not be used for randomness"
                    ),
                    "block.number" => (
                        Severity::Medium,
                        "Block number progression is predictable and should not be used for randomness"
                    ),
                    _ => (Severity::Low, "Block property usage detected"),
                };

                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(
                    Finding::new(
                        format!("block-property-usage-{}", context_var.replace(".", "-")),
                        severity,
                        Confidence::High,
                        format!("Block property usage detected in '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' uses {}. {}",
                            func_name, contract.name, context_var, description
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name),
                );
            }
        }
    }
}

impl Pass for IRTimeVulnerabilityScanner {
    fn name(&self) -> &'static str {
        "ir-time-vulnerabilities"
    }

    fn run_on_contract(
        &mut self,
        contract: &mut Contract,
        _manager: &mut PassManager,
    ) -> Result<()> {
        self.analyze(contract)?;
        Ok(())
    }

    fn required_analyses(&self) -> Vec<AnalysisID> {
        vec![AnalysisID::ControlFlow, AnalysisID::DefUse]
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl Default for IRTimeVulnerabilityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRTimeVulnerabilityScanner {
    fn id(&self) -> &'static str {
        "ir-time-vulnerabilities"
    }

    fn name(&self) -> &'static str {
        "IR Time Vulnerability Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects time-based vulnerabilities including timestamp dependence and block manipulation"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
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
