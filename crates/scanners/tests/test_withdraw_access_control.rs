use anyhow::Result;
use tameshi_scanners::{
    core::{AnalysisContext, ContractInfo, ScannerConfig, Severity},
    representations::RepresentationBundle,
    Scanner, SourceMissingAccessControlScanner,
};

#[test]
fn test_vulnerable_withdraw_detection() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableContract {
    event Withdrawn(address indexed recipient, uint256 amount);

    /// @notice VULNERABLE: Withdraw funds without access control
    /// @dev Anyone can call this function and drain the contract
    /// @param amount The amount to withdraw
    function withdraw(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient contract balance");

        // VULNERABILITY: No check for msg.sender == owner
        // Anyone can withdraw funds!

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, amount);
    }
}"#;

    const FILENAME: &str = "VulnerableContract.sol";

    let contract_info = ContractInfo {
        name: "VulnerableContract".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = SourceMissingAccessControlScanner::new();
    let findings = scanner.scan(&context)?;

    println!(
        "\n[Missing Access Control] Detected {} findings",
        findings.len()
    );

    for finding in &findings {
        println!(
            "  - Type: {} | Severity: {} | Title: {}",
            finding.finding_type, finding.severity, finding.title
        );
        println!("    Description: {}", finding.description);
        for location in &finding.locations {
            if let Some(ref snippet) = location.snippet {
                println!(
                    "    Location: {}:{} - {}",
                    location.file, location.line, snippet
                );
            }
        }
    }

    // Assert that we found the vulnerability
    assert!(
        !findings.is_empty(),
        "Should detect missing access control in withdraw function"
    );

    // Check that we found the high severity unprotected-ether-withdrawal
    let has_ether_withdrawal = findings
        .iter()
        .any(|f| f.finding_type == "unprotected-ether-withdrawal" && f.severity == Severity::High);

    assert!(
        has_ether_withdrawal,
        "Should detect unprotected-ether-withdrawal with High severity"
    );

    Ok(())
}
