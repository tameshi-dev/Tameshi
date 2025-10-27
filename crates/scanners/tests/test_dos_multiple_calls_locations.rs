/// Test for multiple external calls location accuracy

use anyhow::Result;
use tameshi_scanners::{
    core::{ScannerConfig, AnalysisContext},
    representations::RepresentationBundle,
    IRDoSVulnerabilityScanner,
    Scanner,
};
use thalir_transform::transform_solidity_to_ir_with_filename;

#[test]
fn test_multiple_external_calls_location_accuracy() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract TestMultipleCalls {
    mapping(address => uint256) public balances;

    function problematicFunction(
        address recipient1,
        address recipient2,
        address recipient3
    ) external {
        uint256 amount = 1 ether;

        payable(recipient1).transfer(amount);

        payable(recipient2).transfer(amount * 2);

        payable(recipient3).transfer(amount * 3);
    }
}
"#;

    const FILENAME: &str = "TestMultipleCalls.sol";

    let contracts = transform_solidity_to_ir_with_filename(TEST_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let context = AnalysisContext::with_config(bundle, config);

    let scanner = IRDoSVulnerabilityScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[DOS Scanner] Detected {} findings", findings.len());

    let multiple_calls_finding = findings
        .iter()
        .find(|f| f.finding_type == "multiple-external-calls")
        .expect("Should find multiple external calls");

    println!("Finding: {}", multiple_calls_finding.title);
    println!("Description: {}", multiple_calls_finding.description);
    println!("Locations found: {}", multiple_calls_finding.locations.len());

    for location in &multiple_calls_finding.locations {
        println!("  - Line {}: {:?}", location.line, location.snippet);
    }

    assert!(
        multiple_calls_finding.locations.len() >= 3,
        "Should report at least 3 external call locations, got {}",
        multiple_calls_finding.locations.len()
    );

    for location in &multiple_calls_finding.locations {
        if let Some(ref snippet) = location.snippet {
            assert!(
                snippet.contains("transfer") ||
                snippet.contains("call") ||
                snippet.contains("send") ||
                location.line > 0,
                "Location should have relevant snippet or valid line number"
            );
        }
    }

    assert!(
        multiple_calls_finding.description.contains("Line"),
        "Description should list the problematic lines"
    );

    Ok(())
}

#[test]
fn test_commit_reveal_auction_locations() -> Result<()> {
    const AUCTION_CONTRACT: &str = r#"
pragma solidity ^0.8.20;

contract CommitRevealAuction {
    struct Commitment {
        bytes32 commitment;
        uint256 deposit;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;
    address public highestBidder;
    uint256 public highestBid;

    function revealBid(uint256 bidAmount, bytes32 secret) external {
        Commitment storage c = commitments[msg.sender];
        require(c.commitment != bytes32(0), "Not committed");
        require(!c.revealed, "Already revealed");

        bytes32 computedHash = keccak256(abi.encodePacked(bidAmount, secret));
        require(computedHash == c.commitment, "Invalid reveal");

        c.revealed = true;

        if (bidAmount > highestBid && bidAmount <= c.deposit) {
            if (highestBidder != address(0)) {
                payable(highestBidder).transfer(highestBid);
            }

            highestBidder = msg.sender;
            highestBid = bidAmount;
        }

        if (msg.sender != highestBidder) {
            payable(msg.sender).transfer(c.deposit);
        } else if (c.deposit > bidAmount) {
            payable(msg.sender).transfer(c.deposit - bidAmount);
        }
    }
}
"#;

    const FILENAME: &str = "CommitRevealAuction.sol";

    let contracts = transform_solidity_to_ir_with_filename(AUCTION_CONTRACT, Some(FILENAME))?;
    let mut bundle = RepresentationBundle::new();
    for contract in contracts {
        bundle = bundle.add(contract);
    }

    let config = ScannerConfig::default();
    let context = AnalysisContext::with_config(bundle, config);

    let scanner = IRDoSVulnerabilityScanner::new().with_debug(true);
    let findings = scanner.scan(&context)?;

    println!("\n[Auction Test] Detected {} findings", findings.len());

    if let Some(finding) = findings.iter().find(|f| f.finding_type == "multiple-external-calls") {
        println!("Finding: {}", finding.title);
        println!("Locations found: {}", finding.locations.len());

        for location in &finding.locations {
            println!("  - Line {}: {:?}", location.line, location.snippet);

            assert!(
                location.line != 20,
                "Should not report keccak256 line (line 20) as external call location"
            );
        }

        assert!(
            finding.locations.len() >= 2,
            "Should find at least 2 transfer calls in revealBid"
        );
    }

    Ok(())
}