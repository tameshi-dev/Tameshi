# Tameshi

Vulnerability scanner for Solidity smart contracts with real-time VSCode integration.

Tameshi combines source-level, IR-based, and LLM-powered analysis to detect reentrancy, access control issues, arithmetic bugs, and 20+ other vulnerability types.

## Quick Start

### VSCode Extension (Recommended)

**Install from Marketplace:**

1. Search "Tameshi Security Scanner" in the VSCode Extensions view
2. Or install from [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=tameshi.tameshi-vscode)
3. The extension automatically downloads the LSP server on first activation

**First Scan:**

1. Open a `.sol` file in VSCode
2. Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) → `Tameshi: Scan Current File`
3. View findings inline and in the Vulnerability Triage panel

**Verify Installation:**

Create a test file `test.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}
```

Run `Tameshi: Scan Current File`. You should see a **critical reentrancy vulnerability** detected at the external call.

### CLI Installation

**Prerequisites:**

- Rust toolchain (1.70+) - [Install via rustup](https://rustup.rs/)
- Git

**Build from Source:**

```bash
# Clone repository
cd tameshi

# Build release binary
cargo build --release -p tameshi-cli

# Add to PATH or create symlink
export PATH="$PATH:$(pwd)/target/release"
```

**Verify CLI:**

```bash
# Scan a file
./target/release/tameshi scan test.sol

# Export SARIF report
./target/release/tameshi scan test.sol --format sarif -o results.sarif

# Scan entire project
./target/release/tameshi scan contracts/
```

## Features

- **25+ Vulnerability Scanners** - Comprehensive coverage across 9 security categories
- **Multi-Tier Analysis** - 14 source + 10 IR + 1 LLM scanner working together
- **Real-Time VSCode Integration** - Inline diagnostics, findings triage, smart AI rescan
- **Works on Incomplete Code** - No compilation required, scans syntactically invalid Solidity
- **Blazingly Fast** - Scans complete in <1 second
- **SARIF Export** - GitHub Code Scanning integration

## VSCode Configuration (Optional)

Create `.vscode/settings.json`:

```json
{
  "tameshi.scan.onSave": "file",
  "tameshi.llm.enabled": false
}
```

**Enable LLM Analysis:**

```json
{
  "tameshi.llm.enabled": true,
  "tameshi.llm.apiKey": "${env:OPENAI_API_KEY}"
}
```

```bash
export OPENAI_API_KEY="your-api-key"
```

## CLI Usage Examples

```bash
# Scan single file
tameshi scan run contract.sol

# Scan directory
tameshi scan run contracts/

# Export formats
tameshi scan run contract.sol --format json > findings.json
tameshi scan run contract.sol --format markdown > report.md
tameshi scan run contract.sol --format sarif > results.sarif

# With LLM analysis
export OPENAI_API_KEY="your-key"
tameshi analyze contract.sol --format markdown
```

## Documentation

**Full documentation:** [tameshi.dev](https://tameshi.dev)

- [Quick Start Guide](https://tameshi.dev/quick-start.html)
- [VSCode Extension](https://tameshi.dev/vscode.html)
- [All 25+ Scanners](https://tameshi.dev/scanners.html)
- [CLI Reference](https://tameshi.dev/cli.html)
- [Scan Modes](https://tameshi.dev/scan-modes.html)

## License

MIT
