# SC-GUARD: Final Output Example

This document shows what users will see when the project is fully completed.

---

## Command Execution

```bash
sc-guard analyze contracts/MyToken.sol
```

---

## Expected Output

```
================================================================================
SC-GUARD v1.0 - Smart Contract Security Analyzer
================================================================================

[INFO] Analyzing contract: contracts/MyToken.sol
[INFO] Detected Solidity version: 0.8.0


--- PHASE 1: STATIC ANALYSIS ---

[SLITHER] Compiling contract with solc 0.8.0...
[SLITHER] Compilation successful (1.2s)
[SLITHER] Running 70+ security detectors...

Slither Findings:
  [HIGH]   Reentrancy vulnerability detected in withdraw()
  [MEDIUM] Unchecked return value in line 45
  [MEDIUM] Unprotected delegatecall in executeProxy()
  [LOW]    Missing zero-address validation
  [INFO]   Public function could be external

Total: 5 findings (1 high, 2 medium, 1 low, 1 info)


--- PHASE 2: FEATURE EXTRACTION ---

[AST] Parsing contract structure...
[AST] Analyzing function calls and state modifications...
[AST] Building call graph...

Extracted Security Features:
  External Operations:
    • External calls:               7
    • Delegatecalls:                1
    • Send/Transfer operations:     2

  State Modification Patterns:
    • State writes before calls:    3
    • State writes after calls:     2  [CRITICAL PATTERN]

  Function Visibility:
    • Public functions:             8
    • External functions:           4
    • Private functions:            3

  Security Modifiers:
    • Access control present:       YES (onlyOwner)
    • Reentrancy guard present:     NO  [MISSING PROTECTION]

  Dangerous Patterns:
    • Uses tx.origin:               NO
    • Has selfdestruct:             NO
    • Unchecked call returns:       2  [RISKY]

  Call Graph Complexity:
    • Maximum call depth:           3
    • Cycles with external calls:   NO
    • External calls in cycles:     0

[GRAPH] Feature vector: 16 dimensions extracted


--- PHASE 3: ML CLASSIFICATION ---

[MODEL] Loading trained Random Forest classifier...
[MODEL] Predicting vulnerability probabilities...

Vulnerability Analysis:

  1. REENTRANCY
     Probability:  87.3%  [HIGH RISK]
     Indicators:   State writes after external calls detected
                   No reentrancy guard present
                   External calls in withdraw pattern

  2. ACCESS CONTROL
     Probability:  12.5%  [LOW RISK]
     Indicators:   Access modifiers present
                   Owner validation implemented

  3. UNCHECKED EXTERNAL CALLS
     Probability:  68.2%  [MEDIUM-HIGH RISK]
     Indicators:   2 unchecked call return values
                   External calls without validation

  4. DANGEROUS CONSTRUCTS
     Probability:  15.8%  [LOW RISK]
     Indicators:   No tx.origin usage
                   No selfdestruct present
                   Delegatecall detected but limited


--- PHASE 4: RISK SCORING ---

Calculating composite risk score...

Risk Breakdown:
  • Reentrancy risk:              8.7/10  (weight: 35%)
  • Access control risk:          1.3/10  (weight: 25%)
  • Unchecked calls risk:         6.8/10  (weight: 25%)
  • Dangerous constructs risk:    1.6/10  (weight: 15%)

COMPOSITE RISK SCORE: 5.8/10


--- PHASE 5: ENFORCEMENT DECISION ---

Risk Score:  5.8/10
Threshold:   WARN zone (5.0 - 7.5)

DECISION: ⚠️  WARNING - HUMAN REVIEW REQUIRED

Rationale:
  • High reentrancy probability (87.3%) requires attention
  • Medium-high unchecked calls risk (68.2%)
  • No critical dangerous constructs detected
  • Access control adequately implemented

Recommendations:
  1. [CRITICAL] Add reentrancy guard to withdraw() function
     → Implement nonReentrant modifier
     → Follow checks-effects-interactions pattern

  2. [HIGH] Check return values of external calls
     → Line 45: Validate call() return value
     → Line 78: Add require() for send() operation

  3. [MEDIUM] Review delegatecall usage in executeProxy()
     → Ensure delegatecall target is validated
     → Consider access restrictions

  4. [LOW] Consider making public functions external
     → Gas optimization: setBalance(), updateOwner()


================================================================================
ANALYSIS COMPLETE
================================================================================

Summary:
  • Analysis time:        3.4 seconds
  • Features extracted:   16
  • Vulnerabilities:      2 high-risk, 1 medium-risk
  • Final decision:       WARN - Human review required
  • Report saved:         reports/MyToken_20260203_143052.json

================================================================================
```

---

## Alternative Scenarios

### Scenario A: ALLOW (Low Risk Contract)

```
--- PHASE 5: ENFORCEMENT DECISION ---

Risk Score:  2.3/10
Threshold:   ALLOW zone (0.0 - 5.0)

DECISION: ✅ ALLOW - DEPLOYMENT APPROVED

Rationale:
  • All vulnerability probabilities below 25%
  • Proper access controls implemented
  • No reentrancy patterns detected
  • Secure coding practices followed

Minor Suggestions:
  • Consider adding NatSpec documentation
  • Gas optimization opportunities available

Contract is safe for deployment.
```

### Scenario B: BLOCK (Critical Risk Contract)

```
--- PHASE 5: ENFORCEMENT DECISION ---

Risk Score:  9.2/10
Threshold:   BLOCK zone (7.5 - 10.0)

DECISION: 🚫 BLOCK - DEPLOYMENT PROHIBITED

Rationale:
  • CRITICAL: Reentrancy vulnerability (94.7% probability)
  • CRITICAL: Uses tx.origin for authentication
  • HIGH: Unprotected selfdestruct function
  • HIGH: Multiple unchecked external calls

DEPLOYMENT BLOCKED - This contract contains critical vulnerabilities
that must be fixed before deployment.

Required Fixes:
  1. [CRITICAL] Remove tx.origin authentication
  2. [CRITICAL] Protect selfdestruct with access control
  3. [CRITICAL] Implement reentrancy protection
  4. [HIGH] Add checks for all external call returns

DO NOT DEPLOY until all critical issues are resolved.
```

---

## JSON Report Format

When users run: `sc-guard report reports/MyToken_20260203_143052.json`

```json
{
  "contract": "contracts/MyToken.sol",
  "timestamp": "2026-02-03T14:30:52Z",
  "version": "1.0.0",
  "analysis": {
    "compilation": {
      "success": true,
      "solc_version": "0.8.0",
      "duration_seconds": 1.2
    },
    "slither_findings": [
      {
        "severity": "HIGH",
        "detector": "reentrancy-eth",
        "description": "Reentrancy vulnerability detected in withdraw()",
        "location": "contracts/MyToken.sol:42-58",
        "confidence": "high"
      },
      {
        "severity": "MEDIUM",
        "detector": "unchecked-lowlevel",
        "description": "Unchecked return value",
        "location": "contracts/MyToken.sol:45",
        "confidence": "medium"
      }
    ],
    "features": {
      "external_call_count": 7,
      "delegatecall_count": 1,
      "send_transfer_count": 2,
      "state_writes_before_call": 3,
      "state_writes_after_call": 2,
      "public_function_count": 8,
      "external_function_count": 4,
      "private_function_count": 3,
      "has_access_control_modifier": true,
      "has_reentrancy_guard": false,
      "uses_tx_origin": false,
      "has_selfdestruct": false,
      "unchecked_call_count": 2,
      "max_call_depth": 3,
      "has_cycle_with_external_call": false,
      "external_calls_in_cycles": 0
    },
    "predictions": {
      "reentrancy": {
        "probability": 0.873,
        "risk_level": "HIGH",
        "confidence": "high"
      },
      "access_control": {
        "probability": 0.125,
        "risk_level": "LOW",
        "confidence": "high"
      },
      "unchecked_external_call": {
        "probability": 0.682,
        "risk_level": "MEDIUM_HIGH",
        "confidence": "medium"
      },
      "dangerous_construct": {
        "probability": 0.158,
        "risk_level": "LOW",
        "confidence": "medium"
      }
    },
    "risk_score": {
      "composite": 5.8,
      "breakdown": {
        "reentrancy": 8.7,
        "access_control": 1.3,
        "unchecked_calls": 6.8,
        "dangerous_constructs": 1.6
      },
      "weights": {
        "reentrancy": 0.35,
        "access_control": 0.25,
        "unchecked_calls": 0.25,
        "dangerous_constructs": 0.15
      }
    },
    "decision": {
      "result": "WARN",
      "threshold": "5.0-7.5",
      "requires_review": true,
      "reason": "High reentrancy probability requires attention"
    },
    "recommendations": [
      {
        "priority": "CRITICAL",
        "category": "reentrancy",
        "description": "Add reentrancy guard to withdraw() function",
        "fix": "Implement nonReentrant modifier and follow checks-effects-interactions pattern"
      },
      {
        "priority": "HIGH",
        "category": "unchecked_calls",
        "description": "Check return values of external calls",
        "fix": "Add require() statements for call() and send() operations"
      }
    ]
  },
  "metadata": {
    "analysis_duration": 3.4,
    "model_version": "rf_v1.0",
    "training_samples": 137,
    "feature_count": 16
  }
}
```

---

## CLI Help Output

```
$ sc-guard --help

SC-GUARD v1.0 - Smart Contract Security Analyzer
Combining static analysis with interpretable ML for vulnerability detection

USAGE:
  sc-guard analyze <contract>      Analyze a Solidity contract
  sc-guard report <json-file>      View detailed analysis report
  sc-guard batch <directory>       Analyze multiple contracts
  sc-guard train <dataset>         Retrain ML model (advanced)
  sc-guard version                 Show version information
  sc-guard help                    Show this help message

OPTIONS:
  --output, -o <file>              Save report to JSON file
  --verbose, -v                    Show detailed analysis steps
  --threshold <low,high>           Custom risk thresholds (default: 5.0,7.5)
  --no-color                       Disable colored output
  --format <text|json|html>        Output format (default: text)

EXAMPLES:
  # Analyze a single contract
  sc-guard analyze contracts/Token.sol

  # Analyze with custom output
  sc-guard analyze contracts/Token.sol -o report.json -v

  # Analyze all contracts in a directory
  sc-guard batch contracts/ --output reports/

  # View existing report
  sc-guard report reports/Token_20260203.json

THRESHOLDS:
  0.0 - 5.0   : ALLOW  (Green - Safe to deploy)
  5.0 - 7.5   : WARN   (Yellow - Review required)
  7.5 - 10.0  : BLOCK  (Red - Deployment prohibited)

For more information: https://github.com/your-repo/sc-guard
```

---

## Interactive Mode (Future Enhancement)

```
$ sc-guard analyze contracts/MyToken.sol --interactive

[?] Contract compiled successfully. Continue with analysis? (Y/n) y

[?] Detected 1 HIGH severity issue. Show details? (Y/n) y

    HIGH: Reentrancy in withdraw()
    Location: line 42-58

    Vulnerable code:
      42: function withdraw(uint amount) public {
      43:     require(balances[msg.sender] >= amount);
      44:     (bool success, ) = msg.sender.call{value: amount}("");
      45:     require(success);
      46:     balances[msg.sender] -= amount;  // ❌ State change after external call
      47: }

    Fix suggestion:
      42: function withdraw(uint amount) public nonReentrant {
      43:     require(balances[msg.sender] >= amount);
      44:     balances[msg.sender] -= amount;  // ✅ State change before external call
      45:     (bool success, ) = msg.sender.call{value: amount}("");
      46:     require(success);
      47: }

[?] Apply suggested fix? (y/N) n

[?] Continue with ML analysis? (Y/n) y

    ML Prediction: 87.3% probability of reentrancy
    Risk Score: 5.8/10 (WARN)

[?] Save detailed report? (Y/n) y
    Report saved to: reports/MyToken_20260203_143052.json

Analysis complete!
```

---

## Visual Dashboard (Web Interface - Future)

When users run: `sc-guard dashboard`

Opens browser showing:

```
╔════════════════════════════════════════════════════════════╗
║         SC-GUARD Security Dashboard                        ║
╚════════════════════════════════════════════════════════════╝

Recent Analyses:                        Risk Distribution:
┌──────────────────────────────────┐    ┌──────────────────┐
│ ✅ SafeToken.sol     Risk: 2.1   │    │  █████ 45% ALLOW │
│ ⚠️  MyToken.sol      Risk: 5.8   │    │  ███   30% WARN  │
│ ⚠️  Exchange.sol     Risk: 6.3   │    │  ██    25% BLOCK │
│ 🚫 BadContract.sol   Risk: 9.1   │    └──────────────────┘
└──────────────────────────────────┘

Vulnerability Trends:                   Top Issues:
Reentrancy:      ████████████ 12       1. Reentrancy (38%)
Unchecked Calls: ████████     8        2. Unchecked calls (25%)
Access Control:  ████         4        3. Dangerous constructs (20%)
Dangerous:       ██████       6        4. Access control (17%)

[Analyze New Contract] [View Reports] [Model Stats] [Settings]
```

---

This represents the complete user experience when sc-guard is finished!
