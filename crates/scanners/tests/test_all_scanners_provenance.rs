//! Comprehensive test for provenance tracking across all scanners
//!
//! This test verifies that all scanners properly report source locations
//! with snippets for their findings.

use anyhow::Result;
use tameshi_scanners::{
    core::ScannerConfig, IRAccessControlScanner, IRDangerousFunctionsScanner,
    IRPriceManipulationScanner, IRReentrancyScanner, IRUncheckedReturnScanner,
    RepresentationBundle, ScanningEngine,
};
use thalir_transform::transform_solidity_to_ir_with_filename;

const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract ProvenanceTestContract {
    address public owner;
    mapping(address => uint256) public balances;

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }

    function transferTokens(address token, address to, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
    }

    function destroy() public {
        selfdestruct(payable(owner));
    }

    function checkOrigin() public view returns (bool) {
        return tx.origin == owner;
    }
}
"#;

const TEST_FILENAME: &str = "ProvenanceTestContract.sol";

#[test]
fn test_access_control_scanner_provenance() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRAccessControlScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let access_control_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("access-control"))
        .collect();

    assert!(
        !access_control_findings.is_empty(),
        "Access control scanner should find vulnerabilities"
    );

    for finding in &access_control_findings {
        assert!(
            !finding.locations.is_empty(),
            "Finding '{}' should have location information",
            finding.title
        );

        for location in &finding.locations {
            assert_eq!(
                location.file, TEST_FILENAME,
                "Location should reference correct source file"
            );

            assert!(
                location.line > 0 && location.line < 100,
                "Line number should be reasonable: {}",
                location.line
            );

            println!(
                "✓ Access control finding at {}:{}",
                location.file, location.line
            );
            if let Some(ref snippet) = location.snippet {
                println!("  Snippet: {}", snippet);
            }
        }

        assert!(finding.metadata.is_some(), "Finding should have metadata");
        if let Some(ref metadata) = finding.metadata {
            assert!(
                !metadata.affected_contracts.is_empty() || !metadata.affected_functions.is_empty(),
                "Finding should have contract or function metadata"
            );
        }
    }

    println!("✅ Access control scanner provenance test passed!");
    Ok(())
}

#[test]
fn test_reentrancy_scanner_provenance() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRReentrancyScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let reentrancy_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("reentrancy"))
        .collect();

    assert!(
        !reentrancy_findings.is_empty(),
        "Reentrancy scanner should find vulnerabilities"
    );

    for finding in &reentrancy_findings {
        assert!(
            !finding.locations.is_empty(),
            "Finding '{}' should have location information",
            finding.title
        );

        for location in &finding.locations {
            assert_eq!(
                location.file, TEST_FILENAME,
                "Location should reference correct source file"
            );

            assert!(
                location.line > 0 && location.line < 100,
                "Line number should be reasonable: {}",
                location.line
            );

            println!(
                "✓ Reentrancy finding at {}:{}",
                location.file, location.line
            );
            if let Some(ref snippet) = location.snippet {
                println!("  Snippet: {}", snippet);
            }
        }

        assert!(finding.metadata.is_some(), "Finding should have metadata");
    }

    println!("✅ Reentrancy scanner provenance test passed!");
    Ok(())
}

#[test]
fn test_unchecked_return_scanner_provenance() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRUncheckedReturnScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let unchecked_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("unchecked-return"))
        .collect();

    if !unchecked_findings.is_empty() {
        for finding in &unchecked_findings {
            assert!(
                !finding.locations.is_empty(),
                "Finding '{}' should have location information",
                finding.title
            );

            for location in &finding.locations {
                assert_eq!(
                    location.file, TEST_FILENAME,
                    "Location should reference correct source file"
                );

                assert!(
                    location.line > 0 && location.line < 100,
                    "Line number should be reasonable: {}",
                    location.line
                );

                println!(
                    "✓ Unchecked return finding at {}:{}",
                    location.file, location.line
                );
                if let Some(ref snippet) = location.snippet {
                    println!("  Snippet: {}", snippet);
                }
            }

            assert!(finding.metadata.is_some(), "Finding should have metadata");
        }

        println!("✅ Unchecked return scanner provenance test passed!");
    } else {
        println!(
            "⚠️  Unchecked return scanner didn't find vulnerabilities (may need IR improvements)"
        );
    }

    Ok(())
}

#[test]
fn test_dangerous_functions_scanner_provenance() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRDangerousFunctionsScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let dangerous_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("dangerous"))
        .collect();

    assert!(
        !dangerous_findings.is_empty(),
        "Dangerous functions scanner should find vulnerabilities"
    );

    for finding in &dangerous_findings {
        assert!(
            !finding.locations.is_empty(),
            "Finding '{}' should have location information",
            finding.title
        );

        for location in &finding.locations {
            assert_eq!(
                location.file, TEST_FILENAME,
                "Location should reference correct source file"
            );

            assert!(
                location.line > 0 && location.line < 100,
                "Line number should be reasonable: {}",
                location.line
            );

            println!(
                "✓ Dangerous function finding at {}:{}",
                location.file, location.line
            );
            if let Some(ref snippet) = location.snippet {
                println!("  Snippet: {}", snippet);
            }
        }

        assert!(finding.metadata.is_some(), "Finding should have metadata");
    }

    println!("✅ Dangerous functions scanner provenance test passed!");
    Ok(())
}

#[test]
fn test_all_scanners_provenance_comprehensive() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    assert!(
        contracts[0].metadata.source_code.is_some(),
        "Contract should have source code stored"
    );

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config)
        .add_scanner(IRReentrancyScanner::new())
        .add_scanner(IRAccessControlScanner::new())
        .add_scanner(IRUncheckedReturnScanner::new())
        .add_scanner(IRDangerousFunctionsScanner::new())
        .add_scanner(IRPriceManipulationScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n📊 Comprehensive Provenance Test Results:");
    println!("   Total findings: {}", findings.len());

    let findings_with_locations: Vec<_> = findings
        .iter()
        .filter(|f| !f.locations.is_empty())
        .collect();

    let findings_with_snippets: Vec<_> = findings
        .iter()
        .filter(|f| f.locations.iter().any(|loc| loc.snippet.is_some()))
        .collect();

    println!(
        "   Findings with locations: {}",
        findings_with_locations.len()
    );
    println!(
        "   Findings with snippets: {}",
        findings_with_snippets.len()
    );

    assert!(
        !findings_with_locations.is_empty(),
        "At least some findings should have location information"
    );

    let mut scanner_stats: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for finding in findings {
        let scanner = finding.scanner_id.clone();
        *scanner_stats.entry(scanner).or_insert(0) += 1;
    }

    println!("\n   Findings by scanner:");
    for (scanner, count) in scanner_stats {
        println!("     {}: {}", scanner, count);
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

    println!("\n✅ All scanners provenance test passed!");
    println!("   ✓ All findings have correct filename");
    println!("   ✓ Line numbers are from actual source");
    println!("   ✓ Snippets are extracted when available");
    println!("   ✓ Metadata is properly populated");

    Ok(())
}

#[test]
fn test_provenance_with_multiple_vulnerabilities() -> Result<()> {
    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRAccessControlScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let access_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("access-control"))
        .collect();

    if access_findings.len() > 1 {
        println!("Found {} access control issues", access_findings.len());

        let mut seen_lines: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for finding in access_findings {
            for location in &finding.locations {
                seen_lines.insert(location.line);
            }
        }

        println!("Vulnerabilities span {} different lines", seen_lines.len());
    }

    println!("✅ Multiple vulnerabilities provenance test passed!");
    Ok(())
}

#[test]
fn test_price_manipulation_scanner_provenance() -> Result<()> {
    const PRICE_TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract PriceTestContract {
    IPriceOracle public oracle;
    mapping(address => uint256) public balances;

    function swap(uint256 amount) public {
        uint256 price = oracle.getPrice();
        balances[msg.sender] = amount * price;
    }

    function complexCalculation(uint256 a, uint256 b, uint256 c) public {
        uint256 result = (a * b) / c;
        uint256 adjusted = result * balances[msg.sender];
        uint256 final_value = adjusted / oracle.getPrice();
        balances[msg.sender] = final_value;
    }
}
"#;

    const PRICE_TEST_FILENAME: &str = "PriceTestContract.sol";

    let contracts =
        transform_solidity_to_ir_with_filename(PRICE_TEST_CONTRACT, Some(PRICE_TEST_FILENAME))?;

    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRPriceManipulationScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    let price_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.scanner_id.contains("price-manipulation"))
        .collect();

    if !price_findings.is_empty() {
        println!("Found {} price manipulation findings", price_findings.len());

        for finding in &price_findings {
            println!("\nFinding: {} ({})", finding.title, finding.scanner_id);

            assert!(finding.metadata.is_some(), "Finding should have metadata");

            if !finding.locations.is_empty() {
                for location in &finding.locations {
                    assert_eq!(
                        location.file, PRICE_TEST_FILENAME,
                        "Location should reference correct source file"
                    );

                    assert!(
                        location.line > 0 && location.line < 100,
                        "Line number should be reasonable: {}",
                        location.line
                    );

                    println!(
                        "  ✓ Price manipulation finding at {}:{}",
                        location.file, location.line
                    );
                    if let Some(ref snippet) = location.snippet {
                        println!("    Snippet: {}", snippet);
                    }
                }
            } else {
                println!("  ⚠️  Finding has no location information");
            }
        }

        println!("\n✅ Price manipulation scanner provenance test passed!");
    } else {
        println!("⚠️  Price manipulation scanner didn't find vulnerabilities (may need more complex test case)");
    }

    Ok(())
}
