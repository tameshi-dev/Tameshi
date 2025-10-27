use anyhow::Result;
use tameshi_scanners::{
    core::{ScannerConfig, ContractInfo, AnalysisContext, Severity},
    representations::RepresentationBundle,
    SourceMissingAccessControlScanner,
    IRAccessControlScanner,
    Scanner,
};
use thalir_transform::transform_solidity_to_ir_with_filename;

#[test]
fn test_vulnerable_wallet_detection() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableWallet
 * @dev VULNERABLE: Missing access control on critical functions
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 *
 * Vulnerability: The withdraw function lacks proper access control,
 * allowing anyone to withdraw all funds from the contract.
 */
contract VulnerableWallet {
    address public owner;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /// @notice Deposit ETH into the wallet
    function deposit() external payable {
        require(msg.value > 0, "Must deposit some ETH");
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

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

    /// @notice Get the contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice VULNERABLE: Change owner without access control
    /// @dev Anyone can become the owner
    function changeOwner(address newOwner) external {
        // VULNERABILITY: No access control check
        owner = newOwner;
    }
}
"#;

    const FILENAME: &str = "VulnerableWallet.sol";

    println!("\n========================================");
    println!("Testing VulnerableWallet.sol for access control vulnerabilities");
    println!("========================================\n");

    // Test with Source-level scanner
    {
        println!("1. Running SourceMissingAccessControlScanner:");
        println!("   ----------------------------------------");

        let contract_info = ContractInfo {
            name: "VulnerableWallet".to_string(),
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

        println!("   Detected {} findings:", findings.len());

        for finding in &findings {
            println!("\n   ✗ Finding Type: {}", finding.finding_type);
            println!("     Severity: {}", finding.severity);
            println!("     Title: {}", finding.title);
            println!("     Description: {}", finding.description);

            for location in &finding.locations {
                println!("     Location: Line {} - {:?}",
                    location.line,
                    location.snippet.as_deref().unwrap_or("N/A"));
            }
        }

        // Assertions for source-level scanner
        assert!(
            !findings.is_empty(),
            "Source scanner should detect vulnerabilities"
        );

        // Check for withdraw vulnerability
        let has_withdraw_vuln = findings.iter().any(|f|
            f.finding_type == "unprotected-ether-withdrawal" &&
            f.severity == Severity::High &&
            f.title.contains("withdraw")
        );

        assert!(
            has_withdraw_vuln,
            "Should detect unprotected-ether-withdrawal in withdraw function"
        );

        // Check for changeOwner vulnerability
        let has_owner_vuln = findings.iter().any(|f|
            f.finding_type == "unprotected-ownership-change" &&
            f.severity == Severity::Critical &&
            f.title.contains("changeOwner")
        );

        assert!(
            has_owner_vuln,
            "Should detect unprotected-ownership-change in changeOwner function"
        );
    }

    // Test with IR-level scanner
    {
        println!("\n2. Running IRAccessControlScanner:");
        println!("   --------------------------------");

        let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
        let mut bundle = RepresentationBundle::new();
        for contract in contracts {
            println!("   Processing contract: {}", contract.name);
            bundle = bundle.add(contract);
        }

        let config = ScannerConfig::default();
        let context = AnalysisContext::with_config(bundle, config);

        let scanner = IRAccessControlScanner::new();
        let findings = scanner.scan(&context)?;

        println!("   Detected {} findings:", findings.len());

        for finding in &findings {
            println!("\n   ✗ Finding Type: {}", finding.finding_type);
            println!("     Severity: {}", finding.severity);
            println!("     Title: {}", finding.title);
            if let Some(metadata) = &finding.metadata {
                if !metadata.affected_functions.is_empty() {
                    println!("     Functions: {:?}", metadata.affected_functions);
                }
                if !metadata.affected_contracts.is_empty() {
                    println!("     Contracts: {:?}", metadata.affected_contracts);
                }
            }
            println!("     Description: {}", finding.description);
        }

        // Assertions for IR-level scanner
        assert!(
            !findings.is_empty(),
            "IR scanner should detect vulnerabilities"
        );

        // Check that critical functions are flagged
        let vulnerable_functions = findings.iter().filter(|f|
            f.finding_type == "missing-access-control"
        ).count();

        assert!(
            vulnerable_functions > 0,
            "Should detect missing access control in vulnerable functions"
        );
    }

    println!("\n========================================");
    println!("✓ All tests passed!");
    println!("========================================\n");

    Ok(())
}