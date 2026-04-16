# sc-guard — Project Review Talk Structure

> **Audience:** Technical reviewers / academic/industry panel  
> **Total time target:** 20–30 minutes  
> **Format:** Slides + live terminal demo

---

## SECTION 1 — The Problem (3 min)

### Opening Hook (1 min)

> _"In 2016, the DAO hack drained $60 million from an Ethereum smart contract in hours — not because of a server breach, but because of 20 lines of bad Solidity code. In 2022, over $3.8 billion was lost to smart contract exploits."_

- Smart contracts are **immutable** — bugs cannot be patched after deployment
- They control **real financial assets** directly in code
- Manual audits cost $20,000–$100,000+ and take weeks
- Developers need automated, fast, intelligent security analysis **before deployment**

### The Gap

| Problem                             | Impact                                   |
| ----------------------------------- | ---------------------------------------- |
| No fast automated scan for Solidity | Developers skip security checks          |
| Static tools have no learning       | High false-positive rate, ignored alerts |
| No deployment gate                  | Vulnerable contracts go live             |

---

## SECTION 2 — Introducing sc-guard (3 min)

### What is sc-guard?

**sc-guard** is an intelligent smart contract security analysis framework that combines:

- **Static analysis** (Slither) — structural pattern detection
- **Machine learning** (Random Forest) — learned vulnerability classification
- **Risk scoring engine** — weighted 0–10 severity score
- **Policy enforcement** — automated ALLOW / WARN / BLOCK deployment decisions

### Design Philosophy

- Developer-first: runs in a terminal in seconds
- Interpretable: explains _why_ a contract is risky
- Extensible: CLI, REST API, Docker, CI/CD — use it anywhere

### Supported Vulnerability Classes

| Class                | Description                                        |
| -------------------- | -------------------------------------------------- |
| Reentrancy           | Re-entrant external call before state update       |
| Access Control       | Unprotected privileged functions                   |
| Unchecked Call       | Ignored return values from `.call()`               |
| Dangerous Constructs | `tx.origin`, `selfdestruct`, unsafe `delegatecall` |

---

## SECTION 3 — System Architecture (4 min)

### High-Level Architecture Diagram

```
  Solidity Contract
        │
        ▼
┌─────────────────────────────────────────────────────┐
│                   sc-guard Engine                    │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ Slither      │    │   AST Extractor          │   │
│  │ Static       │───▶│   16 security features   │   │
│  │ Analyzer     │    │   Graph Builder          │   │
│  └──────────────┘    │   8 AC features          │   │
│                      └────────────┬─────────────┘   │
│                                   │                  │
│                      ┌────────────▼─────────────┐   │
│                      │  ML Models (Random Forest)│   │
│                      │  • Reentrancy model       │   │
│                      │  • Access Control model   │   │
│                      │  • Unchecked Call model   │   │
│                      │  • Dangerous Construct    │   │
│                      └────────────┬─────────────┘   │
│                                   │                  │
│                      ┌────────────▼─────────────┐   │
│                      │    Risk Scoring Engine    │   │
│                      │    Weighted 0–10 score    │   │
│                      └────────────┬─────────────┘   │
│                                   │                  │
│                      ┌────────────▼─────────────┐   │
│                      │   Policy Enforcement      │   │
│                      │  ALLOW / WARN / BLOCK     │   │
│                      └──────────────────────────┘   │
└──────────────────────────────────┬──────────────────┘
                                   │
           ┌───────────────────────┼───────────────────┐
           ▼                       ▼                   ▼
    Terminal Output          HTML/PDF Report      JSON Output
    (Rich CLI)               (Jinja2)             (CI/CD / API)
```

### Feature Extraction (16 + 8 features)

- Call depth, external call count, state modification patterns
- Function visibility flags, reentrancy indicators
- Access control: unprotected functions, delegatecall protection, tx.origin in auth
- Graph metrics: cycle detection, call centrality

### ML Model Details

- Algorithm: **Random Forest** (100 trees, max_depth=10) — interpretable, no black box
- Baseline: Logistic Regression (comparison)
- Training data: SmartBugs curated dataset (143 contracts, 10 vulnerability categories)
- Output: Per-vulnerability confidence score (0.0–1.0)

### Risk Score Formula

```
Risk = (Reentrancy × 3.0) + (Unchecked Call × 2.0)
     + (Access Control × 2.5) + (Dangerous Construct × 2.5)
Risk normalized to 0–10 scale
```

---

## SECTION 4 — Phase 1: What We Built (5 min)

> _"Phase 1 extended the core engine into a production-ready toolchain."_

### 4.1 — CLI Tool (Core)

```bash
sc-guard scan <contract.sol> [--verbose] [--json] [--report html|pdf]
```

- Runs the full 5-phase pipeline in seconds
- Rich terminal output with color-coded severity
- Multiple output formats for different use cases

### 4.2 — HTML & PDF Reports

- Executive summary with risk score prominently displayed
- Vulnerability breakdown table with confidence scores
- Recommended mitigations per vulnerability
- One command: `sc-guard scan contract.sol --report html`
- Generated from a Jinja2 template → exportable PDF via WeasyPrint

### 4.3 — REST API (FastAPI)

- Programmatic access for integration into any pipeline
- Endpoint: `POST /api/v1/scan` — accepts Solidity code, returns full analysis JSON
- **Security built-in:** API key authentication, rate limiting (10 req/min)
- CORS configured for web frontend integration

### 4.4 — Docker Containerization

- Reproducible, zero-configuration deployment
- All dependencies (Slither, Python, solc) pre-installed
- Run anywhere: `docker-compose up && docker exec sc-guard sc-guard scan contract.sol`
- Non-root container user for security compliance

### 4.5 — CI/CD Integration (GitHub Actions)

Three automated workflows:

| Workflow            | Trigger                  | What it does                              |
| ------------------- | ------------------------ | ----------------------------------------- |
| `security-scan.yml` | Push with `.sol` changes | Auto-scans changed contracts              |
| `test.yml`          | Push / PR                | pytest across Python 3.9/3.10/3.11 + 3 OS |
| `docker-build.yml`  | Tag / main push          | Builds & pushes Docker image to GHCR      |

- Pre-commit hooks: Black, Flake8, isort, Bandit + sc-guard contract scan

### 4.6 — Vulnerable Test Contracts

A library of 7 purposefully vulnerable contracts covering every supported attack class — used for development validation and demo:

- `ReentrancyVulnerable.sol` — DAO-style reentrancy
- `AccessControlVulnerable.sol` — unprotected owner functions
- `DelegatecallVulnerable.sol` — proxy pattern abuse
- `TxOriginVulnerable.sol` — phishing via tx.origin
- `UncheckedCallVulnerable.sol` — silent failure pattern
- `ComplexVulnerable.sol` — real-world combination attack

---

## SECTION 5 — Live Demo (5–8 min)

> Transition: _"Let me show you what this looks like in practice."_

**→ Follow the LIVE_DEMO_SCRIPT.md for exact commands and talking points**

Demo flow:

1. Basic scan — see terminal output
2. Verbose scan — show 5-phase pipeline
3. JSON output — machine-readable for CI
4. HTML report — open in browser
5. REST API call — show programmatic access
6. Docker — show containerized run (optional if Docker available)
7. CI/CD — show the workflow YAML

---

## SECTION 6 — Results & Validation (2 min)

### Model Performance

| Vulnerability       | Accuracy | Precision | Recall | F1   |
| ------------------- | -------- | --------- | ------ | ---- |
| Reentrancy          | ~82%     | High      | High   | Good |
| Access Control      | ~78%     | Medium    | High   | Good |
| Unchecked Call      | ~85%     | High      | High   | High |
| Dangerous Construct | ~80%     | High      | Medium | Good |

_(Refer to MODEL_PERFORMANCE_SUMMARY.md for exact figures)_

### What Works Well

- Static + ML hybrid reduces false positives vs. static-only tools
- Policy enforcement creates a clear deployment gate
- Full pipeline runs in under 5 seconds on a single contract

### Limitations (be honest)

- ML trained on 143 contracts — larger dataset would improve accuracy
- Slither dependency requires compatible solc version
- PDF export requires WeasyPrint system dependencies

---

## SECTION 7 — Roadmap: What's Next (2 min)

### Phase 2 Candidates

| Feature                         | Value                                  |
| ------------------------------- | -------------------------------------- |
| Web Dashboard (React/Streamlit) | Visual analytics for security teams    |
| VS Code Extension               | Inline warnings while coding           |
| SARIF output format             | Native GitHub Security tab integration |
| Larger training dataset         | Better model accuracy                  |
| Gas optimization analysis       | Developer productivity                 |
| Multi-contract project scan     | Real-world DeFi protocol support       |
| Plugin architecture             | Community-contributed analyzers        |

---

## SECTION 8 — Summary & Q&A (2 min)

### What sc-guard delivers

- **Fast:** Full analysis in seconds
- **Intelligent:** ML models, not just pattern matching
- **Actionable:** ALLOW/WARN/BLOCK with explanations
- **Integrated:** CLI + API + Docker + CI/CD
- **Transparent:** Open source, interpretable models

### Closing Statement

> _"sc-guard turns smart contract security from a manual, expensive, post-development activity into an automated, fast, developer-integrated gate that prevents vulnerable contracts from ever reaching the blockchain."_

---

## APPENDIX — Slide Deck Outline

| Slide | Title                   | Content                                                |
| ----- | ----------------------- | ------------------------------------------------------ |
| 1     | Title                   | sc-guard: Intelligent Smart Contract Security Analysis |
| 2     | The Problem             | DAO hack, $3.8B lost, manual audit costs               |
| 3     | The Solution — sc-guard | One-line description + key pillars                     |
| 4     | How It Works            | Architecture diagram                                   |
| 5     | Feature Extraction      | 16+8 features diagram                                  |
| 6     | ML Pipeline             | Random Forest, 4 vulnerability models                  |
| 7     | Risk Scoring & Policy   | Formula + ALLOW/WARN/BLOCK                             |
| 8     | Phase 1: CLI            | Code + screenshot                                      |
| 9     | Phase 1: HTML Reports   | Report screenshot                                      |
| 10    | Phase 1: REST API       | API diagram + curl example                             |
| 11    | Phase 1: Docker         | Dockerfile highlight                                   |
| 12    | Phase 1: CI/CD          | GitHub Actions workflow diagram                        |
| 13    | LIVE DEMO               | (transition to terminal)                               |
| 14    | Model Performance       | Results table                                          |
| 15    | Limitations & Honesty   | What we know needs improvement                         |
| 16    | Roadmap                 | Phase 2 table                                          |
| 17    | Conclusion              | Summary + closing statement                            |
| 18    | Q&A                     | Open floor                                             |
