use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub name: String,
    pub system_prompt: String,
    pub user_prompt_template: String,
    pub focus_areas: Vec<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl PromptTemplate {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            system_prompt: String::new(),
            user_prompt_template: String::new(),
            focus_areas: Vec::new(),
            temperature: None,
            max_tokens: None,
        }
    }

    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = prompt.into();
        self
    }

    pub fn with_user_template(mut self, template: impl Into<String>) -> Self {
        self.user_prompt_template = template.into();
        self
    }

    pub fn with_focus_areas(mut self, areas: Vec<String>) -> Self {
        self.focus_areas = areas;
        self
    }
}

pub struct PromptBuilder {
    templates: HashMap<String, PromptTemplate>,
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptBuilder {
    pub fn new() -> Self {
        let mut builder = Self {
            templates: HashMap::new(),
        };

        builder.load_default_templates();
        builder
    }

    fn load_default_templates(&mut self) {
        self.add_template(Self::general_vulnerability_template());

        self.add_template(Self::reentrancy_template());
        self.add_template(Self::access_control_template());
        self.add_template(Self::overflow_template());
        self.add_template(Self::logic_error_template());
        self.add_template(Self::unchecked_returns_template());
        self.add_template(Self::dos_patterns_template());
        self.add_template(Self::timestamp_dependence_template());
        self.add_template(Self::front_running_template());
        self.add_template(Self::source_analysis_template());

        self.add_template(Self::source_reentrancy_template());
        self.add_template(Self::source_access_control_template());
        self.add_template(Self::source_unchecked_returns_template());
        self.add_template(Self::source_dos_template());
        self.add_template(Self::source_timestamp_template());
        self.add_template(Self::source_front_running_template());
        self.add_template(Self::source_overflow_template());

        self.add_template(Self::tameshi_ir_general_template());
        self.add_template(Self::tameshi_ir_reentrancy_template());
        self.add_template(Self::tameshi_ir_simple_template());

        self.add_template(Self::hybrid_reentrancy_template());
        self.add_template(Self::hybrid_access_control_template());

        self.add_template(Self::o1_position_marked_reentrancy_template());
    }

    pub fn add_template(&mut self, template: PromptTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn build_prompt(
        &self,
        template_name: &str,
        variables: HashMap<String, String>,
    ) -> Result<(String, String)> {
        let template = self
            .templates
            .get(template_name)
            .ok_or_else(|| anyhow::anyhow!("Template '{}' not found", template_name))?;

        let system_prompt = self.substitute_variables(&template.system_prompt, &variables);
        let user_prompt = self.substitute_variables(&template.user_prompt_template, &variables);

        Ok((system_prompt, user_prompt))
    }

    fn substitute_variables(&self, template: &str, variables: &HashMap<String, String>) -> String {
        let mut result = template.to_string();

        for (key, value) in variables {
            let placeholder = format!("{{{}}}", key);
            result = result.replace(&placeholder, value);
        }

        result
    }

    fn general_vulnerability_template() -> PromptTemplate {
        PromptTemplate::new("general_vulnerability")
            .with_system_prompt(GENERAL_SYSTEM_PROMPT)
            .with_user_template(GENERAL_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Security vulnerabilities".to_string(),
                "Logic errors".to_string(),
                "Best practice violations".to_string(),
            ])
    }

    fn reentrancy_template() -> PromptTemplate {
        PromptTemplate::new("reentrancy")
            .with_system_prompt(REENTRANCY_SYSTEM_PROMPT)
            .with_user_template(REENTRANCY_USER_TEMPLATE)
            .with_focus_areas(vec![
                "External calls".to_string(),
                "State changes".to_string(),
                "Call patterns".to_string(),
            ])
    }

    fn access_control_template() -> PromptTemplate {
        PromptTemplate::new("access_control")
            .with_system_prompt(ACCESS_CONTROL_SYSTEM_PROMPT)
            .with_user_template(ACCESS_CONTROL_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Permission checks".to_string(),
                "Modifier usage".to_string(),
                "Admin functions".to_string(),
            ])
    }

    fn overflow_template() -> PromptTemplate {
        PromptTemplate::new("overflow")
            .with_system_prompt(OVERFLOW_SYSTEM_PROMPT)
            .with_user_template(OVERFLOW_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Arithmetic operations".to_string(),
                "Type conversions".to_string(),
                "Boundary checks".to_string(),
            ])
    }

    fn logic_error_template() -> PromptTemplate {
        PromptTemplate::new("logic_error")
            .with_system_prompt(LOGIC_ERROR_SYSTEM_PROMPT)
            .with_user_template(LOGIC_ERROR_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Business logic".to_string(),
                "State transitions".to_string(),
                "Invariant violations".to_string(),
            ])
    }

    fn source_analysis_template() -> PromptTemplate {
        PromptTemplate::new("source_analysis")
            .with_system_prompt(SOURCE_ANALYSIS_SYSTEM_PROMPT)
            .with_user_template(SOURCE_ANALYSIS_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Complete code context".to_string(),
                "Syntax patterns".to_string(),
                "Code quality issues".to_string(),
            ])
    }

    fn unchecked_returns_template() -> PromptTemplate {
        PromptTemplate::new("unchecked_returns")
            .with_system_prompt(UNCHECKED_RETURNS_SYSTEM_PROMPT)
            .with_user_template(UNCHECKED_RETURNS_USER_TEMPLATE)
            .with_focus_areas(vec![
                "External call return values".to_string(),
                "Low-level calls".to_string(),
                "Transfer operations".to_string(),
            ])
    }

    fn dos_patterns_template() -> PromptTemplate {
        PromptTemplate::new("dos_patterns")
            .with_system_prompt(DOS_PATTERNS_SYSTEM_PROMPT)
            .with_user_template(DOS_PATTERNS_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Unbounded loops".to_string(),
                "Gas consumption".to_string(),
                "External dependency failures".to_string(),
            ])
    }

    fn timestamp_dependence_template() -> PromptTemplate {
        PromptTemplate::new("timestamp_dependence")
            .with_system_prompt(TIMESTAMP_DEPENDENCE_SYSTEM_PROMPT)
            .with_user_template(TIMESTAMP_DEPENDENCE_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Block.timestamp usage".to_string(),
                "Block.number dependencies".to_string(),
                "Time-based logic".to_string(),
            ])
    }

    fn front_running_template() -> PromptTemplate {
        PromptTemplate::new("front_running")
            .with_system_prompt(FRONT_RUNNING_SYSTEM_PROMPT)
            .with_user_template(FRONT_RUNNING_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Transaction ordering dependencies".to_string(),
                "Price manipulations".to_string(),
                "MEV vulnerabilities".to_string(),
            ])
    }

    fn source_reentrancy_template() -> PromptTemplate {
        PromptTemplate::new("source_reentrancy")
            .with_system_prompt(SOURCE_REENTRANCY_SYSTEM_PROMPT)
            .with_user_template(SOURCE_REENTRANCY_USER_TEMPLATE)
            .with_focus_areas(vec![
                "External calls in Solidity code".to_string(),
                "State updates after calls".to_string(),
                "CEI pattern violations".to_string(),
            ])
    }

    fn source_access_control_template() -> PromptTemplate {
        PromptTemplate::new("source_access_control")
            .with_system_prompt(SOURCE_ACCESS_CONTROL_SYSTEM_PROMPT)
            .with_user_template(SOURCE_ACCESS_CONTROL_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Function modifiers".to_string(),
                "Permission checks".to_string(),
                "Admin functions".to_string(),
            ])
    }

    fn source_unchecked_returns_template() -> PromptTemplate {
        PromptTemplate::new("source_unchecked_returns")
            .with_system_prompt(SOURCE_UNCHECKED_RETURNS_SYSTEM_PROMPT)
            .with_user_template(SOURCE_UNCHECKED_RETURNS_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Low-level call syntax".to_string(),
                "Return value handling".to_string(),
                "Error checking patterns".to_string(),
            ])
    }

    fn source_dos_template() -> PromptTemplate {
        PromptTemplate::new("source_dos")
            .with_system_prompt(SOURCE_DOS_SYSTEM_PROMPT)
            .with_user_template(SOURCE_DOS_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Loop constructs".to_string(),
                "Array operations".to_string(),
                "Gas limitations".to_string(),
            ])
    }

    fn source_timestamp_template() -> PromptTemplate {
        PromptTemplate::new("source_timestamp")
            .with_system_prompt(SOURCE_TIMESTAMP_SYSTEM_PROMPT)
            .with_user_template(SOURCE_TIMESTAMP_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Block.timestamp usage".to_string(),
                "Now keyword".to_string(),
                "Time-based logic".to_string(),
            ])
    }

    fn source_front_running_template() -> PromptTemplate {
        PromptTemplate::new("source_front_running")
            .with_system_prompt(SOURCE_FRONT_RUNNING_SYSTEM_PROMPT)
            .with_user_template(SOURCE_FRONT_RUNNING_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Price-sensitive functions".to_string(),
                "Order-dependent logic".to_string(),
                "MEV opportunities".to_string(),
            ])
    }

    fn source_overflow_template() -> PromptTemplate {
        PromptTemplate::new("source_overflow")
            .with_system_prompt(SOURCE_OVERFLOW_SYSTEM_PROMPT)
            .with_user_template(SOURCE_OVERFLOW_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Arithmetic operations".to_string(),
                "SafeMath usage".to_string(),
                "Unchecked blocks".to_string(),
            ])
    }

    fn tameshi_ir_general_template() -> PromptTemplate {
        PromptTemplate::new("cranelift-ir-general")
            .with_system_prompt(CRANELIFT_IR_GENERAL_SYSTEM_TEMPLATE)
            .with_user_template(CRANELIFT_IR_USER_TEMPLATE)
            .with_focus_areas(vec![
                "SSA form analysis".to_string(),
                "Control flow patterns".to_string(),
                "External calls and state changes".to_string(),
                "Value dependencies".to_string(),
            ])
    }

    fn tameshi_ir_reentrancy_template() -> PromptTemplate {
        PromptTemplate::new("cranelift-ir-reentrancy")
            .with_system_prompt(CRANELIFT_IR_REENTRANCY_SYSTEM_TEMPLATE)
            .with_user_template(CRANELIFT_IR_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Call instructions with External targets".to_string(),
                "StorageStore and MappingStore after calls".to_string(),
                "Block ordering and dominance".to_string(),
                "Value flow analysis".to_string(),
            ])
    }

    fn tameshi_ir_simple_template() -> PromptTemplate {
        PromptTemplate::new("cranelift-ir-simple")
            .with_system_prompt(CRANELIFT_IR_SIMPLE_SYSTEM_TEMPLATE)
            .with_user_template(CRANELIFT_IR_SIMPLE_USER_TEMPLATE)
            .with_focus_areas(vec![
                "call_ext instruction ordering".to_string(),
                "mapping_store and sstore patterns".to_string(),
                "Sequential execution analysis".to_string(),
            ])
    }

    fn hybrid_reentrancy_template() -> PromptTemplate {
        PromptTemplate::new("hybrid-reentrancy")
            .with_system_prompt(HYBRID_REENTRANCY_SYSTEM_PROMPT)
            .with_user_template(HYBRID_REENTRANCY_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Cross-layer validation".to_string(),
                "Source-level patterns vs IR execution".to_string(),
                "High-confidence dual verification".to_string(),
                "Protection mechanism validation".to_string(),
            ])
    }

    fn hybrid_access_control_template() -> PromptTemplate {
        PromptTemplate::new("hybrid-access-control")
            .with_system_prompt(HYBRID_ACCESS_CONTROL_SYSTEM_PROMPT)
            .with_user_template(HYBRID_ACCESS_CONTROL_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Modifier implementation vs enforcement".to_string(),
                "Visibility declaration vs execution paths".to_string(),
                "Authorization bypass detection".to_string(),
                "Privilege escalation opportunities".to_string(),
            ])
    }

    fn o1_position_marked_reentrancy_template() -> PromptTemplate {
        PromptTemplate::new("o1-position-marked-reentrancy")
            .with_system_prompt(O1_POSITION_MARKED_REENTRANCY_SYSTEM_PROMPT)
            .with_user_template(O1_POSITION_MARKED_REENTRANCY_USER_TEMPLATE)
            .with_focus_areas(vec![
                "Position-marked external calls".to_string(),
                "Position-marked state modifications".to_string(),
                "Temporal ordering analysis (position N < M)".to_string(),
                "Chain-of-thought reentrancy reasoning".to_string(),
            ])
    }
}

const GENERAL_SYSTEM_PROMPT: &str = r#"You are an expert smart contract security auditor analyzing code for vulnerabilities.

YOUR ROLE:
- Identify security vulnerabilities with high precision
- Minimize false positives by requiring strong evidence
- Focus on exploitable issues, not theoretical concerns
- Provide actionable recommendations

ANALYSIS APPROACH:
1. Understand the contract's purpose and architecture
2. Identify trust boundaries and critical operations
3. Analyze control flow and data dependencies
4. Look for violations of security invariants
5. Consider the attack surface and threat model

IMPORTANT:
- Only report issues you can provide specific evidence for
- Include exact code locations for all findings
- Rate confidence based on evidence strength
- Consider the severity in the context of the contract's purpose"#;

const GENERAL_USER_TEMPLATE: &str = r#"Analyze the following {representation_type} for security vulnerabilities:

CONTRACT CONTEXT:
{contract_metadata}

CODE REPRESENTATION:
{code_representation}

ANALYSIS FOCUS:
{focus_areas}

Return a JSON object matching this exact schema:
{json_schema}

Remember to:
- Provide specific line numbers and code references
- Explain the root cause and attack vector clearly
- Include actionable fix recommendations
- Rate confidence honestly based on available evidence"#;

const REENTRANCY_SYSTEM_PROMPT: &str = r#"You are a reentrancy vulnerability specialist analyzing smart contracts.

FOCUS: Detect reentrancy vulnerabilities with high precision.

REENTRANCY PATTERNS TO DETECT:
1. Classic reentrancy: External call before state update
2. Cross-function reentrancy: Vulnerable state shared across functions
3. Cross-contract reentrancy: Vulnerable interactions between contracts

ANALYSIS METHODOLOGY:
- Track all external calls (call, delegatecall, transfer, send)
- Identify state changes after external calls
- Check for proper reentrancy guards
- Analyze the checks-effects-interactions pattern
- Consider callback mechanisms

FALSE POSITIVE AVOIDANCE:
- Verify actual exploitability
- Check for existing protections (mutexes, checks)
- Consider gas limitations
- Validate control flow paths"#;

const REENTRANCY_USER_TEMPLATE: &str = r#"Analyze for REENTRANCY vulnerabilities:

{code_representation}

Focus on:
- External calls and their targets
- State modifications timing
- Reentrancy guard usage
- CEI pattern compliance

Return findings as JSON:
{json_schema}"#;

const ACCESS_CONTROL_SYSTEM_PROMPT: &str = r#"You are an access control vulnerability specialist.

FOCUS: Identify authorization and permission vulnerabilities.

ACCESS CONTROL ISSUES TO DETECT:
1. Missing access controls on critical functions
2. Incorrect modifier implementations
3. Centralization risks
4. Privilege escalation paths
5. Unprotected initialization functions

ANALYSIS APPROACH:
- Map all administrative functions
- Trace permission checks
- Identify role management
- Check modifier correctness
- Analyze ownership transfers"#;

const ACCESS_CONTROL_USER_TEMPLATE: &str = r#"Analyze for ACCESS CONTROL vulnerabilities:

{code_representation}

Focus on:
- Administrative function protections
- Role-based access patterns
- Modifier implementations
- Ownership mechanisms

Return findings as JSON:
{json_schema}"#;

const OVERFLOW_SYSTEM_PROMPT: &str = r#"You are an integer overflow/underflow specialist.

FOCUS: Detect arithmetic vulnerabilities.

OVERFLOW PATTERNS TO DETECT:
1. Unchecked arithmetic operations
2. Type conversion issues
3. Boundary condition violations
4. Timestamp manipulations

ANALYSIS APPROACH:
- Track all arithmetic operations
- Check for SafeMath usage
- Identify unchecked blocks
- Analyze type conversions"#;

const OVERFLOW_USER_TEMPLATE: &str = r#"Analyze for OVERFLOW/UNDERFLOW vulnerabilities:

{code_representation}

Focus on:
- Arithmetic operations without checks
- Type conversions
- Unchecked code blocks
- Boundary conditions

Return findings as JSON:
{json_schema}"#;

const LOGIC_ERROR_SYSTEM_PROMPT: &str = r#"You are a business logic vulnerability specialist.

FOCUS: Detect logical flaws and invariant violations.

LOGIC ERRORS TO DETECT:
1. Incorrect state machine transitions
2. Race conditions
3. Front-running vulnerabilities
4. Economic exploits
5. Invariant violations

ANALYSIS APPROACH:
- Understand the business logic
- Map state transitions
- Identify critical invariants
- Check for atomicity violations"#;

const LOGIC_ERROR_USER_TEMPLATE: &str = r#"Analyze for LOGIC ERRORS:

{code_representation}

Focus on:
- Business logic flaws
- State machine errors
- Race conditions
- Economic vulnerabilities

Return findings as JSON:
{json_schema}"#;

const UNCHECKED_RETURNS_SYSTEM_PROMPT: &str = r#"You are a specialist in detecting unchecked return value vulnerabilities.

FOCUS: Identify functions that ignore return values from external calls.

PATTERNS TO DETECT:
1. Low-level calls (call, delegatecall) without checking success
2. Token transfers without verifying return values
3. External contract interactions ignoring results
4. Silent failures in critical operations

ANALYSIS METHODOLOGY:
- Track all external calls and their return values
- Identify which returns are checked vs ignored
- Assess the criticality of unchecked operations
- Look for error handling patterns

FALSE POSITIVE AVOIDANCE:
- Some calls intentionally ignore returns (e.g., best-effort operations)
- Check if failures are handled through other mechanisms
- Consider the context and purpose of the call"#;

const UNCHECKED_RETURNS_USER_TEMPLATE: &str = r#"Analyze for UNCHECKED RETURN VALUE vulnerabilities:

{code_representation}

Focus on:
- Low-level call operations
- External contract interactions
- Return value handling
- Error propagation patterns

Return findings as JSON:
{json_schema}"#;

const DOS_PATTERNS_SYSTEM_PROMPT: &str = r#"You are a denial-of-service vulnerability specialist.

FOCUS: Detect patterns that could lead to DoS attacks.

DOS PATTERNS TO DETECT:
1. Unbounded loops over dynamic arrays
2. Operations dependent on external calls in loops
3. Block gas limit vulnerabilities
4. Permanent contract freezing conditions
5. Resource exhaustion attacks

ANALYSIS METHODOLOGY:
- Analyze loop bounds and iteration counts
- Check for external dependencies in loops
- Estimate gas consumption patterns
- Identify operations that could fail permanently"#;

const DOS_PATTERNS_USER_TEMPLATE: &str = r#"Analyze for DENIAL OF SERVICE vulnerabilities:

{code_representation}

Focus on:
- Loop implementations and bounds
- Gas consumption patterns
- External dependencies
- Failure conditions

Return findings as JSON:
{json_schema}"#;

const TIMESTAMP_DEPENDENCE_SYSTEM_PROMPT: &str = r#"You are a timestamp manipulation vulnerability specialist.

FOCUS: Detect unsafe dependencies on block timestamps.

TIMESTAMP ISSUES TO DETECT:
1. Using block.timestamp for randomness
2. Critical logic dependent on timestamps
3. Time-based access control
4. Timestamp manipulation for financial gain

ANALYSIS METHODOLOGY:
- Track all uses of block.timestamp and block.number
- Identify critical decisions based on time
- Assess miner manipulation potential
- Check for proper time windows"#;

const TIMESTAMP_DEPENDENCE_USER_TEMPLATE: &str = r#"Analyze for TIMESTAMP DEPENDENCE vulnerabilities:

{code_representation}

Focus on:
- Block.timestamp usage
- Time-based conditions
- Randomness generation
- Critical time dependencies

Return findings as JSON:
{json_schema}"#;

const FRONT_RUNNING_SYSTEM_PROMPT: &str = r#"You are a front-running and MEV vulnerability specialist.

FOCUS: Detect transaction ordering dependencies and MEV opportunities.

FRONT-RUNNING PATTERNS TO DETECT:
1. Price-dependent operations without slippage protection
2. First-come-first-serve reward mechanisms
3. Predictable transaction outcomes
4. Sandwich attack vulnerabilities
5. Auction and trading mechanisms

ANALYSIS METHODOLOGY:
- Identify operations sensitive to ordering
- Check for price manipulation opportunities
- Analyze competitive advantage scenarios
- Look for missing slippage protection"#;

const FRONT_RUNNING_USER_TEMPLATE: &str = r#"Analyze for FRONT-RUNNING vulnerabilities:

{code_representation}

Focus on:
- Transaction ordering dependencies
- Price-sensitive operations
- Competitive mechanisms
- MEV opportunities

Return findings as JSON:
{json_schema}"#;

const SOURCE_REENTRANCY_SYSTEM_PROMPT: &str = r#"You are a reentrancy specialist analyzing raw Solidity source code.

FOCUS: Detect reentrancy vulnerabilities directly in Solidity syntax.

PATTERNS TO IDENTIFY IN SOURCE:
1. .call{value: }() before state changes
2. .transfer() or .send() before state updates  
3. External function calls before balance modifications
4. Cross-function reentrancy via shared state

SOLIDITY-SPECIFIC INDICATORS:
- Look for: msg.sender.call{value: amount}("")
- Check for: balances[msg.sender] -= after external calls
- Identify: require() checks that don't prevent reentrancy
- Find: Missing ReentrancyGuard modifiers"#;

const SOURCE_REENTRANCY_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for REENTRANCY vulnerabilities:

```solidity
{code_representation}
```

Focus on:
- External call patterns (.call, .transfer, .send)
- State update ordering
- Balance modifications
- CEI pattern violations

Return findings as JSON:
{json_schema}"#;

const SOURCE_ACCESS_CONTROL_SYSTEM_PROMPT: &str = r#"You are an access control specialist analyzing raw Solidity source code.

FOCUS: Identify access control vulnerabilities in Solidity syntax.

PATTERNS TO IDENTIFY:
1. Functions without modifiers (onlyOwner, onlyAdmin)
2. Public functions that should be restricted
3. Missing require(msg.sender == owner) checks
4. Unprotected initialization functions

SOLIDITY-SPECIFIC INDICATORS:
- Public/external functions modifying critical state
- Missing modifier declarations
- Incorrect modifier implementations
- Unprotected selfdestruct calls"#;

const SOURCE_ACCESS_CONTROL_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for ACCESS CONTROL vulnerabilities:

```solidity
{code_representation}
```

Focus on:
- Function visibility (public, external, internal, private)
- Modifier usage and implementation
- Owner/admin checks
- Critical function protection

Return findings as JSON:
{json_schema}"#;

const SOURCE_UNCHECKED_RETURNS_SYSTEM_PROMPT: &str = r#"You are analyzing Solidity code for unchecked return values.

FOCUS: Identify ignored return values from external calls.

PATTERNS TO IDENTIFY:
1. address.call() without (bool success, ) =
2. Token transfers without checking return bool
3. External contract calls ignoring results
4. Low-level calls without success validation

SOLIDITY SYNTAX TO CHECK:
- recipient.call{value: amount}("") without checking success
- IERC20(token).transfer() without checking return
- External function calls where return is ignored"#;

const SOURCE_UNCHECKED_RETURNS_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for UNCHECKED RETURN VALUES:

```solidity
{code_representation}
```

Focus on:
- Low-level .call() usage
- ERC20 transfer/transferFrom calls
- External contract interactions
- Success validation patterns

Return findings as JSON:
{json_schema}"#;

const SOURCE_DOS_SYSTEM_PROMPT: &str = r#"You are analyzing Solidity code for denial-of-service vulnerabilities.

FOCUS: Identify DoS patterns in Solidity source code.

PATTERNS TO IDENTIFY:
1. for loops over dynamic arrays without bounds
2. while loops that could run indefinitely
3. Operations that could consume all gas
4. External calls in loops
5. Unbounded data structures

SOLIDITY PATTERNS:
- for(uint i = 0; i < array.length; i++)
- Nested loops over storage
- Push operations in loops
- Revert conditions that block functionality"#;

const SOURCE_DOS_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for DENIAL OF SERVICE vulnerabilities:

```solidity
{code_representation}
```

Focus on:
- Loop implementations and bounds
- Array operations
- Gas-intensive operations
- Blocking conditions

Return findings as JSON:
{json_schema}"#;

const SOURCE_TIMESTAMP_SYSTEM_PROMPT: &str = r#"You are analyzing Solidity code for timestamp dependencies.

FOCUS: Identify unsafe timestamp usage in source code.

PATTERNS TO IDENTIFY:
1. block.timestamp for randomness
2. now keyword (deprecated) usage
3. Time-based access control
4. Critical logic using timestamps

SOLIDITY PATTERNS:
- if(block.timestamp % 2 == 0)
- require(block.timestamp > deadline)
- uint random = uint(keccak256(abi.encode(block.timestamp)))"#;

const SOURCE_TIMESTAMP_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for TIMESTAMP DEPENDENCE:

```solidity
{code_representation}
```

Focus on:
- block.timestamp usage
- now keyword (if present)
- Time-based conditions
- Randomness generation

Return findings as JSON:
{json_schema}"#;

const SOURCE_FRONT_RUNNING_SYSTEM_PROMPT: &str = r#"You are analyzing Solidity code for front-running vulnerabilities.

FOCUS: Identify MEV and front-running opportunities in source.

PATTERNS TO IDENTIFY:
1. Price-setting functions without slippage protection
2. First-come-first-serve rewards
3. Predictable transaction outcomes
4. DEX trading without protection

SOLIDITY PATTERNS:
- Public functions that set prices
- Auction mechanisms
- Token swaps without minAmountOut
- Commit-reveal schemes improperly implemented"#;

const SOURCE_FRONT_RUNNING_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for FRONT-RUNNING vulnerabilities:

```solidity
{code_representation}
```

Focus on:
- Price-sensitive operations
- Order-dependent logic
- Trading functions
- Slippage protection

Return findings as JSON:
{json_schema}"#;

const SOURCE_OVERFLOW_SYSTEM_PROMPT: &str = r#"You are analyzing Solidity code for integer overflow/underflow.

FOCUS: Identify arithmetic vulnerabilities in source code.

PATTERNS TO IDENTIFY:
1. Arithmetic without SafeMath (pre-0.8.0)
2. Unchecked blocks in Solidity 0.8+
3. Type conversions that could overflow
4. Multiplication before division

SOLIDITY PATTERNS:
- a + b, a - b, a * b without checks
- unchecked { ... arithmetic ... }
- uint8 to uint256 conversions
- Downcasting that could truncate"#;

const SOURCE_OVERFLOW_USER_TEMPLATE: &str = r#"Analyze this Solidity contract for INTEGER OVERFLOW/UNDERFLOW:

```solidity
{code_representation}
```

Focus on:
- Arithmetic operations
- unchecked blocks
- Type conversions
- SafeMath usage

Return findings as JSON:
{json_schema}"#;

const SOURCE_ANALYSIS_SYSTEM_PROMPT: &str = r#"You are an expert smart contract auditor analyzing raw Solidity source code.

YOUR ROLE:
- Analyze the complete Solidity source code for vulnerabilities
- Consider the full context and interactions between functions
- Identify patterns that indicate security issues
- Focus on exploitable vulnerabilities with real impact

ANALYSIS APPROACH:
1. Review the overall contract architecture
2. Identify state variables and their protection
3. Analyze function interactions and call flows
4. Check for common vulnerability patterns
5. Consider edge cases and attack vectors"#;

const SOURCE_ANALYSIS_USER_TEMPLATE: &str = r#"Analyze this Solidity smart contract source code for security vulnerabilities:

```solidity
{code_representation}
```

CONTRACT CONTEXT:
{contract_metadata}

ANALYSIS FOCUS:
{focus_areas}

Return a JSON object matching this exact schema:
{json_schema}

Remember to:
- Analyze the complete source code context
- Identify all vulnerability patterns
- Provide specific line references where possible
- Include clear root causes and attack vectors"#;

const CRANELIFT_IR_GENERAL_SYSTEM_TEMPLATE: &str = r#"You are analyzing Cranelift IR (Intermediate Representation) in SSA form for smart contract vulnerabilities.

Cranelift IR uses SSA (Static Single Assignment) form where each value is assigned exactly once.
Key instruction types:
- Call { target: External(...) }: External contract calls
- StorageStore/MappingStore: State modifications
- Assign/Binary/Unary: Value computations
- Branch/ConditionalBranch: Control flow
- Assert/Require: Validation checks

Analyze the IR for security vulnerabilities, focusing on:
1. Reentrancy patterns
2. Access control issues
3. Integer overflow/underflow
4. Unchecked return values
5. DoS patterns

Respond with findings in the exact JSON format specified."#;

const CRANELIFT_IR_REENTRANCY_SYSTEM_TEMPLATE: &str = r#"You are analyzing Cranelift IR with Solidity extensions for reentrancy vulnerabilities in smart contracts.

SOLIDITY-EXTENDED CRANELIFT IR FORMAT:
- Instructions are in SSA (Static Single Assignment) form
- Each instruction executes sequentially within a block
- Values are assigned once: v0, v1, v2, etc.
- Instructions appear in execution order (top to bottom)

SOLIDITY-SPECIFIC INSTRUCTIONS:
1. CONTEXT ACCESS:
   - `get_context msg.sender` - Get transaction sender address
   - `get_context msg.value` - Get sent Ether amount
   - `get_context msg.data` - Get call data

2. STORAGE OPERATIONS:
   - `sstore <slot>, <value>` - Store to storage slot (state variable update)
   - `mapping_store <slot>, <key>, <value>` - Store to mapping (critical state update)

3. EXTERNAL CALLS:
   - `call_ext <target>(<args>)` - External contract call (reentrancy risk)
   - `call <target>(<args>)` - Internal function call (safe)

4. ARITHMETIC & COMPARISON:
   - `iconst.<type> <value>` - Integer constant
   - `icmp <op> <a>, <b>` - Integer comparison (eq, ne, ugt, uge, ult, ule)
   - `udiv.<type> <a>, <b>` - Unsigned division
   - `add.<type>`, `sub.<type>`, `mul.<type>` - Arithmetic operations

5. CONTROL FLOW:
   - `require <condition>, "<message>"` - Solidity require() check
   - `return` - Function return
   - `br` - Unconditional branch
   - `brif <condition>` - Conditional branch

REENTRANCY VULNERABILITY:
A function has reentrancy if an external call occurs BEFORE state is updated.

KEY DETECTION PATTERNS:
- External calls: `call_ext` (calls to external addresses)
- Critical state updates: `mapping_store`, `sstore` (updates storage)
- Safe operations: `mapping_load`, `sload`, `get_context`, `icmp`, `require`

DETECTION METHODOLOGY:
Look at the ORDER of instructions in each function:
1. If `call_ext` appears BEFORE `mapping_store` or `sstore`: VULNERABLE
2. If `mapping_store` or `sstore` appears BEFORE `call_ext`: SAFE
3. Functions with only `call_ext` but no state updates: POTENTIAL (read-only reentrancy)
4. Functions with only state updates but no `call_ext`: SAFE

EXAMPLE - VULNERABLE (Classic Reentrancy):
```
function %withdraw() external {
block0():
    v0 = get_context msg.sender                    // Get caller
    v2 = icmp ugt v1, iconst.i256 0              // Check balance > 0
    require v2, "No balance"                      // Require check
    v3 = get_context msg.sender                   // Get caller again
    v4 = call_ext v3(iconst.i32 0)              // 🔴 EXTERNAL CALL FIRST
    require iconst.i256 1, "Transfer failed"     // Check success
    v5 = get_context msg.sender                   // Get caller
    mapping_store iconst.i256 0, v5, iconst.i256 0  // 🔴 STATE UPDATE AFTER
    return
}
```

EXAMPLE - SAFE (Check-Effects-Interactions):
```
function %withdraw() external {
block0():
    v0 = get_context msg.sender                      // Get caller
    v2 = icmp ugt v1, iconst.i256 0                // Check balance > 0
    require v2, "No balance"                        // Require check
    v3 = get_context msg.sender                     // Get caller
    mapping_store iconst.i256 0, v3, iconst.i256 0    // 🟢 STATE UPDATE FIRST
    v4 = call_ext v3(iconst.i32 0)                // 🟢 EXTERNAL CALL AFTER
    require iconst.i256 1, "Transfer failed"       // Check success
    return
}
```

EXAMPLE - READ-ONLY REENTRANCY:
```
function %getBalance() external view {
block0():
    v0 = get_context msg.sender                    // Get caller
    v2 = call_ext v1(iconst.i32 0)               // 🟡 EXTERNAL CALL in view
    return v3                                      // Return balance
}
```"#;

const CRANELIFT_IR_USER_TEMPLATE: &str = r#"Analyze this Solidity-extended Cranelift IR code for REENTRANCY vulnerabilities:

```
{code_representation}
```

ANALYSIS STEPS:
YOU MUST ANALYZE ALL FUNCTIONS IN THE CONTRACT:
1. Identify EXTERNAL CALLS: Look for `call_ext` instructions in EVERY function
2. Identify STATE UPDATES: Look for `mapping_store` or `sstore` instructions in EVERY function
3. Check EXECUTION ORDER: Determine if external calls occur before state updates in ANY function
4. Classify VULNERABILITY: If ANY function has call_ext before state update, mark as VULNERABLE

CRITICAL: A contract is VULNERABLE if even ONE function has the reentrancy pattern.
Analyze each function individually and report if ANY function is vulnerable.

INSTRUCTION INTERPRETATION:
- `get_context msg.sender` → Safe (context access)
- `mapping_load`, `sload` → Safe (reading state)
- `iconst`, `icmp`, `require` → Safe (computation/validation)
- `call_ext` → CRITICAL (external call - reentrancy risk)
- `mapping_store`, `sstore` → CRITICAL (state update - must occur before external calls)

EXECUTION ORDER ANALYSIS:
Instructions execute sequentially from top to bottom within each block.
Pay special attention to the relative positions of `call_ext` and state update instructions.

**CRITICAL REQUIREMENT**: In every evidence description, you MUST include the exact IR block and instruction references.
Example: "External call at block_0, inst_2 occurs before state update at block_0, inst_5"

You MUST respond with valid JSON matching this exact structure:
```json
{
  "findings": [
    {
      "vuln_type": "reentrancy",
      "severity": "high|medium|low",
      "confidence": "high|medium|low", 
      "title": "string",
      "description": "string",
      "root_cause": "string",
      "attack_vector": "string",
      "recommendation": "string",
      "affected_components": [
        {
          "component_type": "function",
          "name": "function_name"
        }
      ],
      "evidence": [
        {
          "description": "string",
          "code_ref": {
            "file": "contract.sol",
            "line_start": 1,
            "line_end": 10,
            "column_start": 0,
            "column_end": 0,
            "snippet": "call_ext before mapping_store"
          }
        }
      ]
    }
  ],
  "analysis_summary": "Analyzed X functions for reentrancy patterns",
  "coverage_notes": ["Checked call_ext and mapping_store ordering"],
  "requires_further_analysis": []
}
```

If no vulnerabilities: {"findings": [], "analysis_summary": "No reentrancy found", "coverage_notes": ["All functions safe"], "requires_further_analysis": []}"#;

const CRANELIFT_IR_SIMPLE_SYSTEM_TEMPLATE: &str = r#"You are analyzing Cranelift IR intermediate representation for reentrancy vulnerabilities in smart contracts.

IR FORMAT:
- Instructions are in SSA (Static Single Assignment) form
- Each instruction executes sequentially within a block
- Values are assigned once in SSA form
- Instructions appear in execution order (top to bottom)

REENTRANCY VULNERABILITY PATTERNS:
A function is vulnerable to reentrancy if external calls can be exploited to reenter and cause unexpected behavior:

PATTERN 1 - Classic Reentrancy:
- External call (`call_ext`) appears BEFORE state update (`mapping_store`, `sstore`)
- Attacker can reenter during the call and exploit stale state

PATTERN 2 - Complex DeFi Reentrancy:
- Function contains external calls (`call_ext`) that can trigger reentrancy
- Even if some state is updated before the call, incomplete state updates can be exploited
- Look for functions that: update some state → external call → more state updates
- Multiple external calls in sequence without proper state protection

PATTERN 3 - Cross-Function Reentrancy:
- External call allows reentrance into other functions
- State consistency between functions can be broken

- External calls in functions (even view functions) can manipulate state during execution
- View functions that read state during external calls can return stale/manipulated data
- Functions that call external contracts BEFORE state updates, affecting subsequent view function results
- During reentrancy, view functions (getShareValue, getUserPortfolioValue) return incorrect data
- Example: withdraw() calls external → attacker reenters during call → view functions see old state

KEY INSTRUCTIONS TO IDENTIFY:
For Cranelift IR:
- External calls: `call_ext` (calls to external addresses) 
- State updates: `mapping_store` (updates mapping storage), `sstore` (updates storage)
- State reads: `mapping_load`, `sload`

DETECTION METHODOLOGY:
1. Identify all functions with `call_ext` instructions
2. For each function with external calls:
   - Check if state updates happen BEFORE the call (classic vulnerability)
   - Check if the function has INCOMPLETE state updates before external calls
   - Look for multiple external calls that could be exploited in sequence
   - Consider if the external call can reenter and exploit intermediate state
3. Pay special attention to DeFi patterns:
   - Withdrawal functions (balance checks → external call → balance update)
   - Liquidation functions (state cleanup → rewards → refunds)
   - Multi-step operations with external calls in the middle
4. READ-ONLY REENTRANCY DETECTION:
   - ANY function with `call_ext` before state updates is vulnerable to read-only reentrancy
   - Even if the function eventually updates state, the period during external call exposes stale state
   - View functions that depend on the same state become manipulatable during reentrancy
   - Look for vault/pool patterns where view functions calculate shares, prices, or user balances
   - External oracle calls or price feed calls during state transition periods

ANALYSIS GUIDELINES:
- Focus on EXPLOITABLE reentrancy where attacker can cause harm
- Classic pattern: call before state update = HIGH confidence
- Complex pattern: incomplete state + external call = MEDIUM confidence
- READ-ONLY pattern: external call enables view function manipulation = HIGH confidence
- Consider the real-world impact and exploitability
- Report vulnerabilities with specific evidence from the IR
- For read-only reentrancy: ANY external call before state update creates exposure window

Respond with JSON: {"vulnerable": true/false, "confidence": "High/Medium/Low", "details": "explanation"}"#;

const CRANELIFT_IR_SIMPLE_USER_TEMPLATE: &str = r#"Analyze this Cranelift IR representation for reentrancy vulnerabilities:

```
{code_representation}
```

ANALYSIS STEPS:
1. Identify ALL functions containing `call_ext` instructions (external calls)
2. For each function with external calls, analyze the instruction sequence:
   - Look for `call_ext` BEFORE `mapping_store`/`sstore` (classic reentrancy)
   - Look for incomplete state updates before `call_ext` (complex DeFi reentrancy)
   - Check for multiple `call_ext` instructions in sequence
   - Consider DeFi patterns: withdrawals, liquidations, multi-step operations

3. SPECIFIC PATTERNS TO DETECT:
   - withdrawEth/withdraw: balance check → call_ext → balance update (CLASSIC + READ-only reentrancy)
   - borrow: collateral check → call_ext → debt update  
   - liquidate: state cleanup → call_ext (reward) → call_ext (refund)
   - Any function: state read → call_ext → state write
   - READ-ONLY SPECIFIC: Any function with external calls that OTHER view functions depend on
   - Vault/Pool patterns: external call during balance/share calculation period
   - Price oracle interactions during state transitions

4. EVIDENCE REQUIRED:
   - Function name where vulnerability exists
   - Specific instruction sequence showing the vulnerability
   - **CRITICAL**: In evidence description, MUST include exact IR locations like "External call at block_0, inst_2 before state update at block_0, inst_5"
   - Explain how reentrancy could be exploited
   - For read-only reentrancy: identify view functions that would return stale data during external call
   - Specify the exposure window between external call and state update

Remember: Instructions execute sequentially within blocks. Focus on EXPLOITABLE patterns where reentrancy can cause financial damage.

**IMPORTANT**: Every evidence entry MUST include the specific block and instruction numbers (e.g., "block_0, inst_2") in the description field.

Respond with JSON only in this format:
{"vulnerable": true/false, "confidence": "High/Medium/Low", "details": "specific evidence with function names and instruction patterns"}"#;

pub const HYBRID_REENTRANCY_SYSTEM_PROMPT: &str = r#"You are an expert smart contract security auditor with access to both high-level Solidity source code and its corresponding low-level Cranelift IR representation.

MISSION: Analyze both representations to detect reentrancy vulnerabilities with maximum precision.

ANALYSIS APPROACH:
1. SOURCE CODE ANALYSIS:
   - Understand developer intent and high-level control flow
   - Identify external calls (.call, .transfer, .send)
   - Check for reentrancy guards and protection patterns
   - Assess the business logic and interaction patterns

2. CRANELIFT IR ANALYSIS:
   - Verify exact execution order at the instruction level
   - Look for call_ext (external calls) before mapping_store (state updates)
   - Confirm the absence of state updates before external calls
   - Validate control flow and SSA form constraints

3. CROSS-VALIDATION:
   - Reconcile high-level patterns with low-level execution
   - Identify discrepancies between intent and implementation
   - Confirm vulnerabilities exist at both abstraction levels
   - Eliminate false positives through dual verification

REENTRANCY DETECTION CRITERIA:
- Source: External call followed by state update in same function
- IR: call_ext instruction before mapping_store instruction
- Both must agree for a confirmed vulnerability

CONFIDENCE SCORING:
- High: Both source and IR confirm the vulnerability
- Medium: One representation shows vulnerability, other is unclear
- Low: Conflicting evidence between representations"#;

pub const HYBRID_REENTRANCY_USER_TEMPLATE: &str = r#"Analyze this smart contract for REENTRANCY vulnerabilities using both Solidity source and Cranelift IR:

{code_representation}

DUAL-LAYER ANALYSIS REQUIRED:
1. Examine the Solidity source for:
   - External call patterns (.call, .transfer, .send)
   - State modification sequences
   - Protection mechanisms (ReentrancyGuard, checks-effects-interactions)

2. Verify with Cranelift IR:
   - call_ext instruction placement
   - mapping_store instruction ordering
   - Control flow between external calls and state updates

3. Cross-validate findings:
   - Do both representations agree on vulnerability presence?
   - Are there protection mechanisms visible in source but not IR?
   - Is the execution order definitively problematic?

Return findings as JSON:
{json_schema}"#;

pub const HYBRID_ACCESS_CONTROL_SYSTEM_PROMPT: &str = r#"You are analyzing smart contracts for access control vulnerabilities using both Solidity source and Cranelift IR.

DUAL-LAYER ACCESS CONTROL ANALYSIS:

SOURCE LEVEL:
- Function visibility (public, external, internal, private)
- Modifier usage (onlyOwner, onlyAdmin, etc.)
- Role-based access control patterns
- Missing or incorrect protection

IR LEVEL:
- Verification of access checks in execution flow
- Confirmation that checks occur before protected operations
- Detection of bypassed or missing validation paths

FOCUS AREAS:
1. Administrative functions without proper protection
2. Modifier implementation vs actual enforcement
3. State-changing functions accessible to unauthorized users
4. Privilege escalation opportunities"#;

pub const HYBRID_ACCESS_CONTROL_USER_TEMPLATE: &str = r#"Analyze for ACCESS CONTROL vulnerabilities using both representations:

{code_representation}

COMPREHENSIVE ANALYSIS:
1. Source Code Review:
   - Function visibility declarations
   - Modifier implementation and usage
   - Administrative function protection

2. IR Verification:
   - Confirm access checks execute before protected operations
   - Verify no bypass paths exist in control flow
   - Validate modifier enforcement at instruction level

Return findings as JSON:
{json_schema}"#;

const O1_POSITION_MARKED_REENTRANCY_SYSTEM_PROMPT: &str = r#"You are a security expert analyzing Position-Marked Intermediate Representation (IR) for reentrancy vulnerabilities.

IMPORTANT: This IR uses EXPLICIT POSITION MARKERS [0], [1], [2]... to indicate temporal ordering.

O1 REASONING FRAMEWORK:
Use chain-of-thought reasoning to analyze instruction sequences:

Step 1: IDENTIFY external calls
- Look for instructions marked "🔴 EXTERNAL_CALL"
- Note their position markers [N]

Step 2: IDENTIFY state modifications
- Look for instructions marked "🟡 STATE_WRITE"
- Note their position markers [M]

Step 3: COMPARE POSITIONS
- If external call at position [N] and state write at position [M]
- AND N < M (call happens BEFORE state write)
- THEN → REENTRANCY VULNERABILITY

Step 4: ANALYZE CONTROL FLOW
- Check if positions are in same execution path
- Verify no reentrancy guards between [N] and [M]
- Confirm state modification affects call target

REENTRANCY PATTERN:
```
[5] 🔴 EXTERNAL_CALL %result = call External(...)  <- Position 5
...
[8] 🟡 STATE_WRITE mapping_store balances[user] <- 0  <- Position 8

Analysis: 5 < 8 → Call at [5] BEFORE state update at [8] → VULNERABLE
```

SAFE PATTERN (Checks-Effects-Interactions):
```
[3] 🟡 STATE_WRITE mapping_store balances[user] <- 0  <- Position 3
...
[7] 🔴 EXTERNAL_CALL %result = call External(...)  <- Position 7

Analysis: 3 < 7 → State update at [3] BEFORE call at [7] → SAFE
```

KEY RULES:
1. Position markers [N] are SEQUENTIAL - lower numbers execute FIRST
2. Only flag reentrancy if call position < state modification position
3. Ignore calls with no subsequent state modifications
4. Consider cross-function reentrancy (state shared across functions)

CONFIDENCE LEVELS:
- HIGH: Clear position ordering, same function, exploitable state
- MEDIUM: Cross-function, or complex control flow
- LOW: Theoretical pattern without clear exploit path"#;

const O1_POSITION_MARKED_REENTRANCY_USER_TEMPLATE: &str = r#"Analyze this Position-Marked IR for reentrancy vulnerabilities using O1 chain-of-thought reasoning:

{ir_representation}

ANALYSIS PROCEDURE:
1. Scan for 🔴 EXTERNAL_CALL instructions - record positions
2. Scan for 🟡 STATE_WRITE instructions - record positions
3. For each (call_pos, state_pos) pair:
   - If call_pos < state_pos AND same execution path → FLAG as reentrancy
4. Check ⚠️ ORDERING ANALYSIS section for pre-identified patterns
5. Verify exploitability and impact

**CRITICAL**: In evidence descriptions, you MUST include the position markers.
Example: "External call at position [5] occurs before state update at position [8]"

Return findings in JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "reentrancy",
      "severity": "High|Medium|Low",
      "confidence": "High|Medium|Low",
      "description": "Detailed explanation with position analysis",
      "locations": ["Function name, positions [X] and [Y]"],
      "reasoning": "Step-by-step O1 reasoning chain",
      "recommendation": "Move state update to position before external call"
    }}
  ]
}}

IMPORTANT: Use the position markers [N] to reason about temporal ordering!"#;
mod tests {
    use super::*;

    #[test]
    fn test_prompt_builder_templates() {
        let builder = PromptBuilder::new();

        let mut variables = HashMap::new();
        variables.insert(
            "representation_type".to_string(),
            "Cranelift IR".to_string(),
        );
        variables.insert("contract_metadata".to_string(), "Test contract".to_string());
        variables.insert(
            "code_representation".to_string(),
            "function code".to_string(),
        );
        variables.insert("focus_areas".to_string(), "reentrancy".to_string());
        variables.insert("json_schema".to_string(), "{}".to_string());

        let (system, user) = builder.build_prompt("reentrancy", variables).unwrap();

        assert!(system.contains("reentrancy"));
        assert!(user.contains("function code"));
    }

    #[test]
    fn test_variable_substitution() {
        let builder = PromptBuilder::new();

        let template = "Hello {name}, you have {count} messages";
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Alice".to_string());
        vars.insert("count".to_string(), "5".to_string());

        let result = builder.substitute_variables(template, &vars);
        assert_eq!(result, "Hello Alice, you have 5 messages");
    }
}
