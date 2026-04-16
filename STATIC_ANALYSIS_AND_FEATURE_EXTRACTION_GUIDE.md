# Static Analysis and Feature Extraction in sc-guard

## 1. Purpose of This Document

This document explains the two technical foundations that make sc-guard work:

1. Static analysis: understanding Solidity contracts structurally and semantically before execution.
2. Feature extraction: converting that structural information into deterministic numeric signals that machine learning models can use.

In sc-guard, these two stages form the bridge between raw Solidity source code and the later stages of machine learning prediction, risk scoring, and policy enforcement.

At a high level, the pipeline is:

```text
Solidity source
  -> Slither compilation and detector analysis
  -> Contract structure extraction
  -> AST and control-flow feature extraction
  -> Call-graph analysis
  -> Enhanced access-control features
  -> Numeric feature vector
  -> ML vulnerability classifiers
  -> Risk score
  -> ALLOW / WARN / BLOCK decision
```

## 2. Why Static Analysis Matters in Smart Contract Security

Smart contracts are security-critical programs that become effectively immutable once deployed. A traditional web application bug can often be patched after release. A smart contract bug can immediately expose funds, governance privileges, or ownership controls on-chain.

Because of that, static analysis is especially valuable in this domain:

- It inspects source code without executing it.
- It catches risky patterns before deployment.
- It is deterministic and reproducible.
- It can be automated in CI/CD, APIs, and developer tooling.

sc-guard uses static analysis as more than a simple linting layer. It uses static analysis to build a structured representation of contract behavior, then transforms that representation into security-relevant features.

## 3. The Role of Slither in sc-guard

The primary static analysis engine in sc-guard is Slither, integrated in [src/analyzers/slither_analyzer.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/slither_analyzer.py).

Slither was chosen because it provides:

- A mature, industry-standard Solidity analysis framework.
- AST and higher-level program abstractions.
- Built-in vulnerability detectors.
- Programmatic Python APIs that fit sc-guard's architecture.

In this project, Slither is used in four main ways:

1. To compile Solidity contracts safely and consistently.
2. To run built-in vulnerability detectors.
3. To expose contract structure such as functions, modifiers, and state variables.
4. To provide the internal representation needed for feature extraction and call-graph analysis.

### 3.1 Compiler Version Handling

One practical problem with Solidity analysis is compiler-version mismatch. Different contracts target different Solidity versions, and analysis tools often fail if the wrong compiler is used.

sc-guard addresses that in [src/analyzers/slither_analyzer.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/slither_analyzer.py) by:

- Reading the `pragma solidity ...;` statement from the source file.
- Extracting the intended version range.
- Mapping broad version families to a recommended stable compiler version.
- Switching the global compiler version with `solc-select` before running Slither.

This improves robustness when scanning contracts from varied datasets such as SmartBugs.

### 3.2 Static Findings Model

Slither findings are normalized into a project-specific dataclass:

- `VulnerabilityFinding.type`
- `VulnerabilityFinding.severity`
- `VulnerabilityFinding.function_name`
- `VulnerabilityFinding.line_number`
- `VulnerabilityFinding.description`

This structure exists in [src/analyzers/slither_analyzer.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/slither_analyzer.py) and gives the rest of the system a stable internal representation regardless of how Slither formats raw detector results.

### 3.3 Detector Mapping Strategy

Slither exposes many detectors. sc-guard does not use all of them directly. Instead, it maps selected Slither detector names into the project's four high-level vulnerability classes:

- `reentrancy`
- `access_control`
- `unchecked_external_call`
- `dangerous_construct`

Examples from [src/analyzers/slither_analyzer.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/slither_analyzer.py):

- `reentrancy-eth` -> `reentrancy`
- `reentrancy-no-eth` -> `reentrancy`
- `suicidal` -> `access_control`
- `controlled-delegatecall` -> `access_control`
- `unchecked-lowlevel` -> `unchecked_external_call`
- `tx-origin` -> `dangerous_construct`

This mapping is important because it aligns low-level tool output with the ML and risk-scoring architecture of the project.

### 3.4 Extracting Contract Structure

Beyond vulnerability findings, the analyzer also extracts structural contract information such as:

- Functions and their visibility.
- State variables.
- Modifiers.
- External call counts.

That structural layer is the input to feature engineering. Static analysis is therefore not just a reporting stage in sc-guard. It is the raw material for the ML pipeline.

## 4. Static Analysis Responsibilities in the End-to-End Scan

When the `scan` command in [src/cli/main.py](c:/Users/prema/Desktop/Projects/sc-guard/src/cli/main.py) runs, the early part of the pipeline is:

1. Construct a `SlitherAnalyzer` for the target contract.
2. Run `analyze()` to compile and detect findings.
3. Pass the Slither object into `ASTFeatureExtractor`.
4. Build graph metrics using `CallGraphBuilder`.
5. Convert everything into a numeric feature vector.

That means static analysis in sc-guard has two outputs:

- Human-readable findings used in reporting and enforcement context.
- Machine-readable features used by the classifiers.

## 5. What Feature Extraction Means in This Project

Feature extraction is the process of converting Solidity code characteristics into fixed numeric values.

A machine learning model cannot directly learn from raw Solidity text in this implementation. Instead, sc-guard builds a compact, interpretable feature vector where each feature represents a security-relevant code property.

The design goals of the feature layer are:

- Deterministic: the same contract always yields the same feature values.
- Explainable: each dimension corresponds to a meaningful code pattern.
- Compact: small enough for classical ML models to learn effectively.
- Security-aware: engineered around known smart contract vulnerability mechanisms.

The core implementation is in [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py).

## 6. The Core 16-Dimensional Feature Vector

The central data structure is `ContractFeatures` in [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py).

It defines 16 features:

1. `external_call_count`
2. `delegatecall_count`
3. `send_transfer_count`
4. `state_writes_before_call`
5. `state_writes_after_call`
6. `public_function_count`
7. `external_function_count`
8. `private_function_count`
9. `has_access_control_modifier`
10. `has_reentrancy_guard`
11. `uses_tx_origin`
12. `has_selfdestruct`
13. `unchecked_call_count`
14. `max_call_depth`
15. `has_cycle_with_external_call`
16. `external_calls_in_cycles`

These are exported as a NumPy vector through `to_vector()` and named through `feature_names()`.

The 16-feature design is deliberate. It is expressive enough to capture key vulnerability patterns, but still compact enough to train interpretable Random Forest and Logistic Regression models.

## 7. Feature Categories and Their Security Meaning

### 7.1 External Call Features

The first group captures how often and in what form a contract interacts with external code.

Features:

- `external_call_count`
- `delegatecall_count`
- `send_transfer_count`

Why they matter:

- External calls increase attack surface because control leaves the current contract.
- `delegatecall` is particularly dangerous because it executes code in the caller's storage context.
- `send` and `transfer` are relevant value-transfer patterns that often appear in withdrawal logic.

The implementation in [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py) checks:

- `function.internal_calls`
- `function.external_calls_as_expressions`
- `function.high_level_calls`
- `function.calls_as_expression`

This multi-path inspection is useful because Solidity call behavior can surface through different Slither abstractions depending on syntax and compiler representation.

### 7.2 State Modification Features

These features capture whether state writes happen before or after external calls.

Features:

- `state_writes_before_call`
- `state_writes_after_call`

This category directly supports reentrancy reasoning.

Safe design generally follows the Checks-Effects-Interactions pattern:

1. Validate preconditions.
2. Update internal state.
3. Interact with external contracts.

If state updates occur after an external call, the contract may be vulnerable to reentrant callbacks.

The extractor analyzes function control-flow nodes and tracks whether an external call has already been seen. Then it counts state-variable writes relative to that point. This logic is implemented in [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py).

This is one of the strongest examples of domain-specific feature engineering in the project: the feature is not arbitrary, it directly encodes a known security principle.

### 7.3 Function Visibility Features

These features quantify exposed entry points.

Features:

- `public_function_count`
- `external_function_count`
- `private_function_count`

Why they matter:

- Public and external functions increase callable surface area.
- Private functions reduce direct exposure.
- Vulnerability risk often depends not only on what code does, but on how reachable it is.

For example, a dangerous operation in a private helper is not equivalent to the same operation in a public payable function.

### 7.4 Modifier Features

These features capture whether defensive modifiers are present.

Features:

- `has_access_control_modifier`
- `has_reentrancy_guard`

These are Boolean features represented numerically as `0` or `1` in the feature vector.

Why they matter:

- Access-control modifiers such as `onlyOwner`, `restricted`, or similar patterns can reduce exploitation risk for critical functions.
- Reentrancy guards such as `nonReentrant` are a direct mitigation signal.

The extractor checks modifiers at the contract and function level and converts their presence into machine-readable binary indicators.

### 7.5 Dangerous Construct Features

These features record explicit use of historically dangerous Solidity mechanisms.

Features:

- `uses_tx_origin`
- `has_selfdestruct`
- `unchecked_call_count`

Why they matter:

- `tx.origin` in authentication logic is a classic phishing and authorization mistake.
- `selfdestruct` is highly privileged and dangerous if exposed incorrectly.
- Unchecked low-level calls can silently fail and break control assumptions.

This category makes the feature set closely aligned with real exploit classes rather than generic software metrics.

### 7.6 Graph Features

The last three features summarize function-call graph behavior.

Features:

- `max_call_depth`
- `has_cycle_with_external_call`
- `external_calls_in_cycles`

These come from [src/analyzers/graph_builder.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/graph_builder.py).

Why they matter:

- Reentrancy is fundamentally a graph and control-flow problem, not just a local syntax problem.
- Deep call chains increase complexity and audit difficulty.
- Cycles that include external calls are especially important because they model callback-style control flow.

## 8. AST Feature Extraction Process

The `ASTFeatureExtractor.extract()` method in [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py) performs the core extraction process.

For each concrete contract in the Slither compilation unit, it does the following:

1. Counts external calls.
2. Analyzes state modifications around those calls.
3. Extracts function visibility statistics.
4. Detects dangerous code patterns.
5. Detects access-control and reentrancy modifiers.
6. Enriches the result with graph-analysis metrics.

The resulting `ContractFeatures` object is then converted into a NumPy vector and passed to the ML stage.

This design has two strong engineering properties:

- Each extraction step has a clear security rationale.
- The final representation remains small and interpretable.

## 9. Call Graph Analysis and Reentrancy Reasoning

A particularly important part of feature extraction is graph analysis in [src/analyzers/graph_builder.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/graph_builder.py).

### 9.1 Why Graph Analysis Is Needed

Many security tools stop at local pattern detection. That can miss cross-function or callback-driven behavior.

Reentrancy often involves a sequence such as:

```text
Function A
  -> external call
  -> attacker callback
  -> Function A or Function B re-entered
```

That is naturally represented as a cycle in the function interaction graph.

### 9.2 Graph Construction Model

The call graph builder uses:

- Nodes: fully qualified function identifiers.
- Edges: call relationships between functions.
- Per-node metadata: number of external calls in each function.

It constructs the adjacency representation by traversing Slither's:

- `high_level_calls`
- `internal_calls`

### 9.3 Metrics Produced

The analysis returns a `CallGraphMetrics` object containing:

- `has_cycles`
- `cycle_count`
- `max_call_depth`
- `functions_in_cycles`
- `external_calls_in_cycles`

Among these, `external_calls_in_cycles` is especially valuable because it combines two conditions that are individually weaker but jointly stronger:

- cyclic control flow
- external interaction

That makes it a high-signal reentrancy-oriented feature.

## 10. Enhanced Access-Control Feature Engineering

The project includes an additional module for access-control-specific signals: [src/analyzers/enhanced_features.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/enhanced_features.py).

This module adds 8 more features designed to improve detection of access-control vulnerabilities.

The enhanced features are:

1. `unprotected_critical_functions`
2. `protected_critical_functions`
3. `delegatecall_without_protection`
4. `tx_origin_in_auth`
5. `missing_onlyowner_on_selfdestruct`
6. `public_state_changing_functions`
7. `external_payable_functions`
8. `missing_constructor_protection`

### 10.1 Why the Enhanced Features Exist

Access control is harder than reentrancy to capture with simple generic features because it depends heavily on intent and privilege boundaries.

For example, a public function is not automatically vulnerable. It becomes interesting when it:

- changes privileged state,
- transfers value,
- uses delegatecall,
- destroys the contract,
- or lacks an ownership/authentication guard.

The enhanced feature set encodes exactly those distinctions.

### 10.2 Critical Function Detection

One key helper in [src/analyzers/enhanced_features.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/enhanced_features.py) is `_is_critical_function()`.

A function is treated as critical if it:

- modifies important state such as owner/admin/balance-like variables,
- performs value transfer,
- uses `selfdestruct`,
- or uses `delegatecall`.

This is a practical definition for security review because these are exactly the kinds of operations that should rarely be exposed without strict authorization.

### 10.3 Access-Control Detection Logic

The enhanced module identifies protection through two mechanisms:

- explicit access-control modifiers on the function,
- inline checks such as `require(msg.sender == owner)` or similar patterns.

This matters because many Solidity codebases implement authorization directly in function bodies rather than through named modifiers.

### 10.4 Interaction Features

The same module also defines derived interaction features in `create_feature_interactions()`:

- `critical_unprotected_ratio`
- `delegatecall_risk`
- `auth_vulnerability_score`

These interaction terms capture combined risk conditions that may be more predictive than raw counts alone.

## 11. From Feature Extraction to Dataset Construction

The feature layer is operationalized for model training in [src/data/feature_builder.py](c:/Users/prema/Desktop/Projects/sc-guard/src/data/feature_builder.py).

The dataset-building process is:

1. Load all contracts from the SmartBugs curated dataset.
2. Run Slither analysis on each contract.
3. Extract the 16 core features.
4. Attach labels derived from `vulnerabilities.json` or category fallback.
5. Store the result in a tabular dataset.

The output row structure is:

- contract metadata such as name and category
- one column per feature
- one label column per vulnerability type

This transformation is essential because it turns raw source files into a supervised-learning table suitable for scikit-learn.

## 12. Dataset Source and Labels

The dataset loader in [src/data/dataset_loader.py](c:/Users/prema/Desktop/Projects/sc-guard/src/data/dataset_loader.py) reads the SmartBugs curated dataset and its `vulnerabilities.json` annotations.

Its responsibilities include:

- discovering Solidity contracts recursively,
- assigning category labels from directory structure,
- loading JSON-based vulnerability annotations,
- exposing a contract iterator used by the feature builder.

This is important in the overall static-analysis story because it ensures the exact same analysis pipeline used at scan time is also used during training data creation.

## 13. Why Classical ML Fits This Feature Design

The machine learning side of this project is implemented in [src/ml/train_model.py](c:/Users/prema/Desktop/Projects/sc-guard/src/ml/train_model.py).

The selected models are:

- Logistic Regression as a baseline.
- Random Forest as the primary classifier.

This fits the feature extraction design well.

Reasons:

- The feature vector is compact and structured, which suits classical ML.
- Random Forest handles non-linear interactions between code patterns.
- Feature importances remain interpretable, which is valuable in a security tool.
- The dataset size is moderate, so deep learning would be harder to justify.

This is one of the strongest architectural choices in the project: instead of trying to learn directly from raw Solidity text, it uses static-analysis-guided features as semantically meaningful inputs.

## 14. Multi-Label Vulnerability Detection Strategy

sc-guard does not train one single monolithic classifier for every issue at once. It uses a separate model per vulnerability type.

In [src/cli/main.py](c:/Users/prema/Desktop/Projects/sc-guard/src/cli/main.py), the scan pipeline loads separate model files for:

- reentrancy
- access_control
- unchecked_call
- dangerous_construct

Each model receives the same extracted feature vector but learns a different decision boundary.

This architecture is sensible because:

- each vulnerability class has different causal patterns,
- the same code signal may matter differently for different attack classes,
- and it simplifies evaluation and model improvement per class.

## 15. How the CLI Uses Static Analysis and Features at Runtime

The runtime flow in [src/cli/main.py](c:/Users/prema/Desktop/Projects/sc-guard/src/cli/main.py) is:

1. Validate the input Solidity file.
2. Run `SlitherAnalyzer.analyze()`.
3. Create `ASTFeatureExtractor(analyzer.slither)`.
4. Call `extract()` to obtain `ContractFeatures`.
5. Run `CallGraphBuilder(analyzer.slither).analyze()` and add graph metrics.
6. Convert the feature object to a NumPy vector.
7. Feed that vector to the trained models.
8. Aggregate probabilities into a risk score.
9. Produce an ALLOW, WARN, or BLOCK enforcement result.

This means the static-analysis and feature-extraction stages are not offline-only research steps. They are part of the production scan path used by the CLI, reports, API, and CI integrations.

## 16. Security Value of the Feature Set

The feature set is valuable because it captures several layers of security semantics at once.

### 16.1 Syntax-Level Signals

Examples:

- presence of `tx.origin`
- occurrence of `delegatecall`
- use of `selfdestruct`

These are direct code-pattern indicators.

### 16.2 Structural Signals

Examples:

- number of public and external functions
- modifier presence
- critical function exposure

These describe how the contract is organized and exposed.

### 16.3 Behavioral Signals

Examples:

- state writes after external calls
- unchecked low-level calls
- value-transfer patterns

These reflect dangerous execution behavior.

### 16.4 Relational Signals

Examples:

- call depth
- cycle detection
- external calls inside cycles

These capture cross-function interaction patterns that single-line inspection would miss.

The strength of sc-guard is that it combines all four layers into a single coherent representation.

## 17. Why This Approach Is Explainable

One of the main advantages of this project design is explainability.

If a model predicts that a contract is vulnerable, reviewers can reason about why by inspecting:

- the extracted feature values,
- the static findings from Slither,
- the graph metrics,
- and the model's most important features.

For example, if a contract is flagged for reentrancy and has:

- high `external_call_count`,
- nonzero `state_writes_after_call`,
- positive `has_cycle_with_external_call`,
- and elevated `external_calls_in_cycles`,

then the prediction is easy to justify in security terms.

That is much easier to defend in a review than a black-box neural model over raw source text.

## 18. Practical Engineering Benefits

The static-analysis-driven feature approach also has engineering advantages:

- Reproducible outputs for the same source input.
- Reasonable training cost on a laptop CPU.
- Simple serialization into CSV datasets and `.pkl` models.
- Natural integration into terminal tools, APIs, and CI/CD.
- Easier debugging than token- or embedding-based approaches.

This makes the project realistic for a production-style academic or engineering prototype.

## 19. Current Design Boundaries and Honest Limitations

For review purposes, it is useful to be explicit about the current limits of the approach.

### 19.1 Dependence on Slither and Compiler Compatibility

The entire static-analysis layer depends on successful Solidity compilation through Slither. If compiler versions or source layouts are unusual, extraction can fail.

### 19.2 Hand-Engineered Feature Scope

The current features are strong for the targeted vulnerability classes, but they are still hand-engineered. That means the system is best at patterns it was explicitly designed to represent.

### 19.3 Project-Level and Cross-Contract Semantics

The current design is strongest on single-contract or per-file analysis. More advanced project-level reasoning such as multi-contract trust boundaries, proxy architectures, or protocol-wide state flows would require richer graph representations.

### 19.4 Dataset Size

The training pipeline uses the SmartBugs curated dataset, which is useful but not massive. More contracts and more diverse labeling would likely improve robustness.

### 19.5 Access-Control Complexity

Access control is particularly subtle. The enhanced feature module addresses this by adding specialized signals, but complex ownership frameworks, custom authorization systems, and indirect privilege flows remain challenging.

## 20. Why the Static Analysis and Feature Extraction Design Is Strong

From an architectural standpoint, this part of the project is strong for five reasons.

1. It uses a credible analysis foundation: Slither.
2. It turns code into interpretable, security-aware features rather than generic text embeddings.
3. It incorporates both local code patterns and graph-level relational reasoning.
4. It supports both training-time dataset construction and runtime scanning with the same abstractions.
5. It is practical to explain, debug, and extend.

For a project review, this is an important point: the value of sc-guard is not only that it uses machine learning, but that it uses machine learning on top of carefully engineered security semantics.

## 21. Suggested Review Summary

If you need a short spoken summary for a presentation, you can use this:

> sc-guard begins with static analysis using Slither to compile the contract, detect known risky patterns, and expose the program structure. It then performs deterministic feature extraction, converting security-relevant properties such as external calls, state updates, modifiers, dangerous constructs, and call-graph cycles into a fixed numeric feature vector. That vector becomes the input to separate Random Forest models for each vulnerability class. This design keeps the system explainable, reproducible, and grounded in real smart contract security semantics rather than treating Solidity as raw text.

## 22. Relevant Source Files

For quick reference during review preparation, the main implementation files are:

- [src/analyzers/slither_analyzer.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/slither_analyzer.py)
- [src/analyzers/ast_extractor.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/ast_extractor.py)
- [src/analyzers/graph_builder.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/graph_builder.py)
- [src/analyzers/enhanced_features.py](c:/Users/prema/Desktop/Projects/sc-guard/src/analyzers/enhanced_features.py)
- [src/data/feature_builder.py](c:/Users/prema/Desktop/Projects/sc-guard/src/data/feature_builder.py)
- [src/data/dataset_loader.py](c:/Users/prema/Desktop/Projects/sc-guard/src/data/dataset_loader.py)
- [src/ml/train_model.py](c:/Users/prema/Desktop/Projects/sc-guard/src/ml/train_model.py)
- [src/cli/main.py](c:/Users/prema/Desktop/Projects/sc-guard/src/cli/main.py)

## 23. Final Takeaway

Static analysis and feature extraction are the technical core of sc-guard.

They are the reason the project is more than a wrapper around a detector and more than a generic ML classifier. Static analysis gives the system deep program understanding. Feature extraction turns that understanding into a structured security representation. Everything else in the system, including vulnerability prediction, risk scoring, reporting, API responses, and enforcement decisions, depends on this foundation.
