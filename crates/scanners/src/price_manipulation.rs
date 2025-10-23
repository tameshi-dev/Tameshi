//! Price manipulation vulnerability Scanner using IR analysis

use crate::core::{Confidence, Finding, Severity};
use anyhow::Result;
use thalir_core::{
    analysis::{
        cursor::ScannerCursor,
        pass::{AnalysisID, Pass, PassManager},
    },
    contract::Contract,
    instructions::{CallTarget, Instruction},
    values::Value,
};

pub struct IRPriceManipulationScanner {
    findings: Vec<Finding>,
}

impl IRPriceManipulationScanner {
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
            let mut external_calls = Vec::new();
            let mut storage_reads = Vec::new();
            let mut arithmetic_ops = Vec::new();
            let mut price_related_patterns = Vec::new();
            let mut oracle_interactions = Vec::new();

            for block_id in cursor.traverse_dom_order() {
                let block = function.body.blocks.get(&block_id).unwrap();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    match instruction {
                        Instruction::Call {
                            target,
                            args,
                            result,
                            ..
                        } => {
                            external_calls.push((block_id, idx, target, args.len(), result));

                            if self.is_potential_oracle_call(target) {
                                oracle_interactions.push((block_id, idx, target));
                            }
                        }

                        Instruction::StorageLoad { result, key, .. } => {
                            storage_reads.push((block_id, idx, result, key));
                        }

                        Instruction::Mul {
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
                            arithmetic_ops.push((block_id, idx, result, left, right, instruction));
                        }

                        Instruction::Require { condition, message } => {
                            if self.is_price_related_check(condition, message) {
                                price_related_patterns.push((
                                    block_id,
                                    idx,
                                    "price_check",
                                    message.clone(),
                                ));
                            }
                        }

                        _ => {}
                    }
                }
            }

            self.analyze_single_oracle_dependency(contract, func_name, &oracle_interactions);
            self.analyze_price_calculation_risks(
                contract,
                func_name,
                &arithmetic_ops,
                &storage_reads,
            );
            self.analyze_flashloan_risks(
                contract,
                func_name,
                &external_calls,
                &price_related_patterns,
            );
            self.analyze_oracle_freshness(
                contract,
                func_name,
                &oracle_interactions,
                &price_related_patterns,
            );
            self.analyze_price_validation(contract, func_name, &price_related_patterns);
        }

        Ok(self.findings.clone())
    }

    fn is_potential_oracle_call(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::External(address) => {
                let addr_str = format!("{:?}", address).to_lowercase();
                addr_str.contains("oracle")
                    || addr_str.contains("price")
                    || addr_str.contains("feed")
                    || addr_str.contains("chainlink")
                    || addr_str.contains("aggregator")
                    || addr_str.contains("latestround")
            }
            CallTarget::Library(name) => {
                let name_lower = name.to_lowercase();
                name_lower.contains("oracle")
                    || name_lower.contains("price")
                    || name_lower.contains("feed")
                    || name_lower.contains("chainlink")
                    || name_lower.contains("aggregator")
                    || name_lower.contains("latestround")
            }
            CallTarget::Internal(name) => {
                let name_lower = name.to_lowercase();
                name_lower.contains("oracle")
                    || name_lower.contains("price")
                    || name_lower.contains("feed")
                    || name_lower.contains("getprice")
                    || name_lower.contains("latestround")
            }
            CallTarget::Builtin(_) => false,
        }
    }

    fn is_price_related_check(&self, _condition: &Value, message: &str) -> bool {
        let message_lower = message.to_lowercase();
        message_lower.contains("price")
            || message_lower.contains("oracle")
            || message_lower.contains("rate")
            || message_lower.contains("exchange")
            || message_lower.contains("swap")
            || message_lower.contains("slippage")
            || message_lower.contains("deviation")
    }

    fn analyze_single_oracle_dependency(
        &mut self,
        contract: &Contract,
        func_name: &str,
        oracle_interactions: &[(thalir_core::block::BlockId, usize, &CallTarget)],
    ) {
        let oracle_count = oracle_interactions.len();

        if oracle_count == 1 {
            let (block_id, idx, _) = oracle_interactions[0];
            let location =
                super::provenance::get_instruction_location(contract, func_name, block_id, idx);

            self.findings.push(Finding::new(
                "single-oracle-dependency".to_string(),
                Severity::High,
                Confidence::Medium,
                format!("Single oracle dependency in '{}'", func_name),
                format!(
                    "Function '{}' in contract '{}' relies on a single price oracle. This creates a single point of failure and potential for price manipulation attacks. Consider using multiple oracle sources and implementing price deviation checks",
                    func_name, contract.name
                ),
            )
            .with_location(location)
            .with_contract(&contract.name)
            .with_function(func_name));
        }
    }

    fn analyze_price_calculation_risks(
        &mut self,
        contract: &Contract,
        func_name: &str,
        arithmetic_ops: &[(
            thalir_core::block::BlockId,
            usize,
            &Value,
            &Value,
            &Value,
            &Instruction,
        )],
        storage_reads: &[(
            thalir_core::block::BlockId,
            usize,
            &Value,
            &thalir_core::instructions::StorageKey,
        )],
    ) {
        let calc_count = arithmetic_ops.len();
        let storage_count = storage_reads.len();

        if calc_count > 3 && storage_count > 0 {
            if let Some((block_id, idx, _, _, _, _)) = arithmetic_ops.first() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "complex-price-calculation".to_string(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Complex price calculation in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' performs {} arithmetic operations with {} storage reads for price calculations. Complex calculations increase the attack surface for price manipulation",
                        func_name, contract.name, calc_count, storage_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }

        for (block_id, idx, _, _left, right, instruction) in arithmetic_ops {
            if let Instruction::Div { .. } = instruction {
                if self.is_potentially_manipulable_value(right) {
                    let location = super::provenance::get_instruction_location(
                        contract, func_name, *block_id, *idx,
                    );

                    self.findings.push(Finding::new(
                        "division-by-manipulable-value".to_string(),
                        Severity::Medium,
                        Confidence::Medium,
                        format!("Risky division in '{}'", func_name),
                        format!(
                            "Function '{}' in contract '{}' divides by a potentially manipulable value. This could lead to division by zero or price manipulation attacks",
                            func_name, contract.name
                        ),
                    )
                    .with_location(location)
                    .with_contract(&contract.name)
                    .with_function(func_name));
                }
            }
        }
    }

    fn is_potentially_manipulable_value(&self, value: &Value) -> bool {
        match value {
            Value::StorageRef(_) => true,
            Value::Temp(_) => true, // Assuming temps often hold external call results
            Value::Constant(_) => false,
            _ => false,
        }
    }

    fn analyze_flashloan_risks(
        &mut self,
        contract: &Contract,
        func_name: &str,
        external_calls: &[(
            thalir_core::block::BlockId,
            usize,
            &CallTarget,
            usize,
            &Value,
        )],
        price_patterns: &[(thalir_core::block::BlockId, usize, &str, String)],
    ) {
        let call_count = external_calls.len();
        let price_check_count = price_patterns.len();

        if call_count > 2 && price_check_count > 0 {
            if let Some((block_id, idx, _, _, _)) = external_calls.first() {
                let location = super::provenance::get_instruction_location(
                    contract, func_name, *block_id, *idx,
                );

                self.findings.push(Finding::new(
                    "flashloan-manipulation-risk".to_string(),
                    Severity::High,
                    Confidence::Medium,
                    format!("Flash loan manipulation risk in '{}'", func_name),
                    format!(
                        "Function '{}' in contract '{}' makes {} external calls and has {} price-related operations. This pattern is vulnerable to flash loan attacks where attackers can manipulate prices within a single transaction",
                        func_name, contract.name, call_count, price_check_count
                    ),
                )
                .with_location(location)
                .with_contract(&contract.name)
                .with_function(func_name));
            }
        }
    }

    fn analyze_oracle_freshness(
        &mut self,
        contract: &Contract,
        func_name: &str,
        oracle_interactions: &[(thalir_core::block::BlockId, usize, &CallTarget)],
        price_patterns: &[(thalir_core::block::BlockId, usize, &str, String)],
    ) {
        if oracle_interactions.is_empty() {
            return;
        }

        let has_timestamp_checks = price_patterns.iter().any(|(_, _, _, message)| {
            message.to_lowercase().contains("stale")
                || message.to_lowercase().contains("fresh")
                || message.to_lowercase().contains("timestamp")
                || message.to_lowercase().contains("time")
        });

        if !has_timestamp_checks {
            let (block_id, idx, _) = oracle_interactions[0];
            let location =
                super::provenance::get_instruction_location(contract, func_name, block_id, idx);

            self.findings.push(Finding::new(
                "no-oracle-freshness-check".to_string(),
                Severity::Medium,
                Confidence::High,
                format!("No oracle freshness validation in '{}'", func_name),
                format!(
                    "Function '{}' in contract '{}' uses oracle data without validating freshness. Stale price data can be exploited for arbitrage and manipulation attacks. Implement timestamp checks for oracle updates",
                    func_name, contract.name
                ),
            )
            .with_location(location)
            .with_contract(&contract.name)
            .with_function(func_name));
        }
    }

    fn analyze_price_validation(
        &mut self,
        contract: &Contract,
        func_name: &str,
        price_patterns: &[(thalir_core::block::BlockId, usize, &str, String)],
    ) {
        if price_patterns.is_empty() {
            return;
        }

        let has_deviation_check = price_patterns.iter().any(|(_, _, _, message)| {
            message.to_lowercase().contains("deviation")
                || message.to_lowercase().contains("threshold")
                || message.to_lowercase().contains("range")
        });

        let has_slippage_check = price_patterns.iter().any(|(_, _, _, message)| {
            message.to_lowercase().contains("slippage")
                || message.to_lowercase().contains("minimum")
                || message.to_lowercase().contains("expected")
        });

        if !has_deviation_check {
            self.findings.push(Finding::new(
                "no-price-deviation-check".to_string(),
                Severity::Medium,
                Confidence::Medium,
                format!("No price deviation validation in '{}'", func_name),
                format!(
                    "Function '{}' in contract '{}' doesn't validate price deviations. Implement checks to detect abnormal price movements that could indicate manipulation",
                    func_name, contract.name
                ),
            )
            .with_contract(&contract.name)
            .with_function(func_name));
        }

        if !has_slippage_check {
            self.findings.push(Finding::new(
                "no-slippage-protection".to_string(),
                Severity::Low,
                Confidence::Medium,
                format!("No slippage protection in '{}'", func_name),
                format!(
                    "Function '{}' in contract '{}' may lack slippage protection. Consider implementing minimum output amount checks",
                    func_name, contract.name
                ),
            )
            .with_contract(&contract.name)
            .with_function(func_name));
        }
    }
}

impl Pass for IRPriceManipulationScanner {
    fn name(&self) -> &'static str {
        "ir-price-manipulation"
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

impl Default for IRPriceManipulationScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::core::Scanner for IRPriceManipulationScanner {
    fn id(&self) -> &'static str {
        "ir-price-manipulation"
    }

    fn name(&self) -> &'static str {
        "IR Price Manipulation Scanner"
    }

    fn description(&self) -> &'static str {
        "Detects price manipulation vulnerabilities including oracle issues, flash loan attacks, and price validation problems"
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
