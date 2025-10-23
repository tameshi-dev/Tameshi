//! Comprehensive test for location provenance feature
//!
//! This test verifies that:
//! 1. Source filenames are correctly propagated through the transformation pipeline
//! 2. Findings include proper location information
//! 3. Contract and function names are properly associated with findings
//! 4. Multiple findings from the same file maintain correct provenance

use anyhow::Result;
use tameshi_scanners::{
    core::ScannerConfig, IRAccessControlScanner, IRReentrancyScanner, IRUncheckedReturnScanner,
    RepresentationBundle, ScanningEngine,
};
use thalir_transform::transform_solidity_to_ir_with_filename;

const TEST_SOURCE: &str = include_str!("test_location_provenance.sol");
const TEST_FILENAME: &str = "test_location_provenance.sol";

#[test]
fn test_location_provenance_complete() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_SOURCE, Some(TEST_FILENAME))?;

    assert!(!contracts.is_empty(), "Should have at least one contract");

    let contract = &contracts[0];
    assert_eq!(contract.name, "LocationProvenanceTest");
    assert_eq!(
        contract.metadata.source_file.as_deref(),
        Some(TEST_FILENAME),
        "Source filename should be set in contract metadata"
    );

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config)
        .add_scanner(IRReentrancyScanner::new())
        .add_scanner(IRAccessControlScanner::new())
        .add_scanner(IRUncheckedReturnScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    assert!(!findings.is_empty(), "Should detect vulnerabilities");

    let findings_with_locations: Vec<_> = findings
        .iter()
        .filter(|f| !f.locations.is_empty())
        .collect();

    assert!(
        !findings_with_locations.is_empty(),
        "At least some findings should have location information"
    );

    println!(
        "Found {} findings with locations out of {} total",
        findings_with_locations.len(),
        findings.len()
    );

    for finding in &findings_with_locations {
        for location in &finding.locations {
            assert_eq!(
                location.file, TEST_FILENAME,
                "Location should reference the correct source file. Found: {}",
                location.file
            );
        }
    }

    let findings_with_metadata: Vec<_> = findings.iter().filter(|f| f.metadata.is_some()).collect();

    for finding in &findings_with_metadata {
        if let Some(ref metadata) = finding.metadata {
            assert!(
                !metadata.affected_contracts.is_empty() || !metadata.affected_functions.is_empty(),
                "Finding should have contract or function metadata"
            );
        }
    }

    let reentrancy_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("reentrancy"))
        .collect();

    if !reentrancy_findings.is_empty() {
        let finding = reentrancy_findings[0];

        assert!(
            !finding.locations.is_empty(),
            "Reentrancy finding should have location information"
        );

        assert_eq!(finding.locations[0].file, TEST_FILENAME);

        if let Some(ref metadata) = finding.metadata {
            assert!(
                metadata
                    .affected_contracts
                    .contains(&"LocationProvenanceTest".to_string())
                    || metadata
                        .affected_functions
                        .contains(&"vulnerableWithdraw".to_string()),
                "Reentrancy finding should reference contract or function"
            );
        }

        println!("✓ Reentrancy finding has proper provenance:");
        println!("  - File: {}", finding.locations[0].file);
        println!("  - Line: {}", finding.locations[0].line);
        if let Some(ref snippet) = finding.locations[0].snippet {
            println!("  - Snippet: {}", snippet);
        }
    }

    let access_control_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("access-control"))
        .collect();

    if !access_control_findings.is_empty() {
        let finding = access_control_findings[0];

        for location in &finding.locations {
            assert_eq!(
                location.file, TEST_FILENAME,
                "Access control finding should reference correct file"
            );
        }

        println!("✓ Access control finding has proper provenance:");
        println!("  - Scanner: {}", finding.scanner_id);
        println!("  - Title: {}", finding.title);
    }

    let all_files: std::collections::HashSet<_> = findings
        .iter()
        .flat_map(|f| &f.locations)
        .map(|loc| &loc.file)
        .collect();

    assert_eq!(
        all_files.len(),
        1,
        "All findings should reference the same source file"
    );
    assert!(
        all_files.contains(&TEST_FILENAME.to_string()),
        "All findings should reference the test file"
    );

    for finding in findings {
        for location in &finding.locations {
            assert!(
                location.line < 1000,
                "Line number (IR index) should be reasonable: {}",
                location.line
            );
        }
    }

    println!("\n✅ All location provenance tests passed!");
    println!("   - Filename propagation: ✓");
    println!("   - Location information: ✓");
    println!("   - Metadata association: ✓");
    println!("   - Multiple findings: ✓");

    Ok(())
}

#[test]
fn test_filename_without_provenance() -> Result<()> {
    let contracts = thalir_transform::transform_solidity_to_ir(TEST_SOURCE)?;

    assert!(!contracts.is_empty());

    let contract = &contracts[0];

    assert_eq!(
        contract.metadata.source_file, None,
        "Source file should be None when not provided"
    );

    Ok(())
}

#[test]
fn test_provenance_with_multiple_contracts() -> Result<()> {
    let source = r#"
        pragma solidity ^0.8.0;

        contract ContractA {
            mapping(address => uint256) public balances;

            function withdraw() public {
                (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
        }

        contract ContractB {
            address public owner;

            function setOwner(address newOwner) public {
                owner = newOwner; // Missing access control
            }
        }
    "#;

    let filename = "multi_contract_test.sol";
    let contracts = transform_solidity_to_ir_with_filename(source, Some(filename))?;

    for contract in &contracts {
        assert_eq!(
            contract.metadata.source_file.as_deref(),
            Some(filename),
            "Contract {} should have correct source file",
            contract.name
        );
    }

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config)
        .add_scanner(IRReentrancyScanner::new())
        .add_scanner(IRAccessControlScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    for finding in findings {
        for location in &finding.locations {
            assert_eq!(
                location.file, filename,
                "All findings should reference the same source file"
            );
        }
    }

    println!("✅ Multiple contract provenance test passed!");

    Ok(())
}

#[test]
fn test_location_snippets() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_SOURCE, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRReentrancyScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let findings_with_snippets: Vec<_> = findings
        .iter()
        .filter(|f| f.locations.iter().any(|loc| loc.snippet.is_some()))
        .collect();

    assert!(
        !findings_with_snippets.is_empty(),
        "Some findings should have code snippets"
    );

    for finding in findings_with_snippets {
        for location in &finding.locations {
            if let Some(ref snippet) = location.snippet {
                assert!(!snippet.is_empty(), "Snippet should not be empty");
                println!("Snippet: {}", snippet);
            }
        }
    }

    println!("✅ Location snippet test passed!");

    Ok(())
}
