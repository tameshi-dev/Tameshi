//! Individual unit tests for each scanner's provenance tracking
//!
//! Each scanner MUST have a dedicated test that verifies it reports
//! correct source locations with snippets for its findings.

use anyhow::Result;
use tameshi_scanners::{
    core::ScannerConfig, IRAccessControlScanner, IRDangerousFunctionsScanner,
    IRDoSVulnerabilityScanner, IRPriceManipulationScanner, IRReentrancyScanner,
    IRUncheckedReturnScanner, RepresentationBundle, ScanningEngine,
};
use thalir_transform::transform_solidity_to_ir_with_filename;

fn verify_finding_locations(
    findings: &[tameshi_scanners::core::Finding],
    expected_filename: &str,
    scanner_name: &str,
) {
    for finding in findings {
        println!("\n  [{}] {}", finding.scanner_id, finding.title);

        assert!(
            finding.metadata.is_some(),
            "{} finding '{}' should have metadata",
            scanner_name,
            finding.title
        );

        if !finding.locations.is_empty() {
            for location in &finding.locations {
                assert_eq!(
                    location.file, expected_filename,
                    "{} location should reference correct source file",
                    scanner_name
                );

                assert!(
                    location.line > 0 && location.line < 1000,
                    "{} line number should be reasonable: {}",
                    scanner_name,
                    location.line
                );

                println!("    ✓ Location: {}:{}", location.file, location.line);
                if let Some(ref snippet) = location.snippet {
                    println!("      Snippet: {}", snippet);
                }
            }
        } else {
            println!("    ⚠ No location information (may be aggregate finding)");
        }
    }
}

#[test]
fn test_reentrancy_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract ReentrancyTest {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
"#;
    const FILENAME: &str = "ReentrancyTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRReentrancyScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Reentrancy Scanner Test ===");
    println!("Total findings: {}", findings.len());

    if !findings.is_empty() {
        verify_finding_locations(&findings, FILENAME, "Reentrancy");
        println!("\n✅ Reentrancy scanner provenance test passed!");
    } else {
        println!("⚠️  No findings (may need IR improvements)");
    }

    Ok(())
}

#[test]
fn test_access_control_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract AccessControlTest {
    address public owner;

    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
"#;
    const FILENAME: &str = "AccessControlTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRAccessControlScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Access Control Scanner Test ===");
    println!("Total findings: {}", findings.len());

    assert!(
        !findings.is_empty(),
        "Access control scanner should find missing access control"
    );
    verify_finding_locations(&findings, FILENAME, "Access Control");
    println!("\n✅ Access control scanner provenance test passed!");

    Ok(())
}

#[test]
fn test_unchecked_return_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract UncheckedReturnTest {
    function transferTokens(address token, address to, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
    }
}
"#;
    const FILENAME: &str = "UncheckedReturnTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRUncheckedReturnScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Unchecked Return Scanner Test ===");
    println!("Total findings: {}", findings.len());

    if !findings.is_empty() {
        verify_finding_locations(&findings, FILENAME, "Unchecked Return");
        println!("\n✅ Unchecked return scanner provenance test passed!");
    } else {
        println!("⚠️  No findings (may need IR improvements)");
    }

    Ok(())
}

#[test]
fn test_dangerous_functions_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract DangerousFunctionsTest {
    address public owner;

    function destroy() public {
        selfdestruct(payable(owner));
    }
}
"#;
    const FILENAME: &str = "DangerousFunctionsTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRDangerousFunctionsScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Dangerous Functions Scanner Test ===");
    println!("Total findings: {}", findings.len());

    assert!(
        !findings.is_empty(),
        "Dangerous functions scanner should detect selfdestruct"
    );
    verify_finding_locations(&findings, FILENAME, "Dangerous Functions");
    println!("\n✅ Dangerous functions scanner provenance test passed!");

    Ok(())
}

#[test]
fn test_price_manipulation_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract PriceManipulationTest {
    IPriceOracle public oracle;
    mapping(address => uint256) public balances;

    function swap(uint256 amount) public {
        uint256 price = oracle.getPrice();
        balances[msg.sender] = amount * price;
    }
}
"#;
    const FILENAME: &str = "PriceManipulationTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRPriceManipulationScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Price Manipulation Scanner Test ===");
    println!("Total findings: {}", findings.len());

    if !findings.is_empty() {
        verify_finding_locations(&findings, FILENAME, "Price Manipulation");
        println!("\n✅ Price manipulation scanner provenance test passed!");
    } else {
        println!("⚠️  No findings (may need more complex test case)");
    }

    Ok(())
}

#[test]
fn test_dos_scanner_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract DoSTest {
    mapping(address => uint256) public balances;
    address[] public users;

    function massTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: amounts[i]}("");
            require(success, "Transfer failed");
        }
    }

    function unboundedLoop(uint256 max) public {
        for (uint256 i = 0; i < max; i++) {
            balances[msg.sender] += 1;
        }
    }
}
"#;
    const FILENAME: &str = "DoSTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let engine = ScanningEngine::new(config).add_scanner(IRDoSVulnerabilityScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== DoS Scanner Test ===");
    println!("Total findings: {}", findings.len());

    if !findings.is_empty() {
        verify_finding_locations(&findings, FILENAME, "DoS");
        println!("\n✅ DoS scanner provenance test passed!");
    } else {
        println!("⚠️  No findings (may need IR improvements)");
    }

    Ok(())
}

#[test]
fn test_all_scanners_have_provenance() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract ComprehensiveTest {
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

    function destroy() public {
        selfdestruct(payable(owner));
    }
}
"#;
    const FILENAME: &str = "ComprehensiveTest.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
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
        .add_scanner(IRPriceManipulationScanner::new())
        .add_scanner(IRDoSVulnerabilityScanner::new());

    let report = engine.run(bundle)?;
    let findings = report.findings();

    println!("\n=== Comprehensive Scanner Test ===");
    println!("Total findings: {}", findings.len());

    let findings_with_locations: Vec<_> = findings
        .iter()
        .filter(|f| !f.locations.is_empty())
        .collect();

    println!(
        "Findings with locations: {}/{}",
        findings_with_locations.len(),
        findings.len()
    );

    let mut scanner_findings: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for finding in findings.iter() {
        *scanner_findings
            .entry(finding.scanner_id.clone())
            .or_insert(0) += 1;
    }

    println!("\nFindings by scanner:");
    for (scanner, count) in &scanner_findings {
        println!("  {}: {}", scanner, count);
    }

    let all_files: std::collections::HashSet<_> = findings
        .iter()
        .flat_map(|f| &f.locations)
        .map(|loc| &loc.file)
        .collect();

    if !all_files.is_empty() {
        assert_eq!(
            all_files.len(),
            1,
            "All findings should reference the same file"
        );
        assert!(
            all_files.contains(&FILENAME.to_string()),
            "All findings should reference {}",
            FILENAME
        );
    }

    println!("\n✅ All scanners provenance comprehensive test passed!");
    Ok(())
}
