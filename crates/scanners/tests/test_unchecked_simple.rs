use anyhow::Result;
use tameshi_scanners::{
    core::{AnalysisContext, ContractInfo, ScannerConfig},
    representations::RepresentationBundle,
    Scanner, UncheckedArithmeticScanner,
};

#[test]
fn test_real_contract_from_demo() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IntegerVulnerabilities {
    mapping(address => uint256) public balances;

    function depositUnchecked(uint256 amount) external {
        unchecked {
            balances[msg.sender] += amount;
        }
    }

    function withdrawUnchecked(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        unchecked {
            balances[msg.sender] -= amount;
        }
    }
}
"#;

    const FILENAME: &str = "IntegerVulnerabilities.sol";

    let contract_info = ContractInfo {
        name: "IntegerVulnerabilities".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!(
        "\n[unchecked-arithmetic] Detected {} findings",
        findings.len()
    );

    for finding in &findings {
        println!("  - {}: {}", finding.severity, finding.title);
        for location in &finding.locations {
            if let Some(ref snippet) = location.snippet {
                println!(
                    "    Location: {}:{} - {}",
                    location.file, location.line, snippet
                );
            }
        }
    }

    assert!(
        !findings.is_empty(),
        "Should detect unchecked arithmetic vulnerabilities in real contract"
    );

    Ok(())
}
