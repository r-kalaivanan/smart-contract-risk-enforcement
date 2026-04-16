# sc-guard — Live Demo Script

> **Purpose:** Step-by-step script for live demo during project review  
> **Duration:** 5–8 minutes  
> **Environment:** Windows PowerShell with `.venv` activated  
> **Prereq check time:** ~2 minutes before the session starts

---

## PRE-DEMO SETUP (Do this 10 minutes before)

Run these silently before anyone is watching:

```powershell
# 1. Navigate to project
cd C:\Users\prema\Desktop\Projects\sc-guard

# 2. Activate virtual environment
.venv\Scripts\Activate.ps1

# 3. Install/verify all dependencies
pip install -r requirements.txt -q

# 4. Verify sc-guard command works
sc-guard --version

# 5. Create outputs folder if missing
New-Item -ItemType Directory -Force -Path outputs

# 6. Clear any stale reports so demo looks clean
Remove-Item outputs\*.html -ErrorAction SilentlyContinue
Remove-Item outputs\*.json -ErrorAction SilentlyContinue
```

**Expected output from step 4:** `sc-guard version X.X.X`

> ⚠️ If `sc-guard` is not found, run: `pip install -e .`

---

## DEMO STEP 1 — "Let's scan a smart contract"

_Talking point: "Here's the simplest use case — a developer runs one command before committing."_

**Command:**

```powershell
sc-guard scan test_contracts/ReentrancyVulnerable.sol
```

**What the audience sees:**

- Rich-formatted terminal table
- Vulnerability predictions (Reentrancy: HIGH)
- Risk score (expect 7–10 out of 10)
- **BLOCK** deployment decision in red

**Say:**

> _"In under 5 seconds, sc-guard has analyzed the contract's AST, run it through our static analyzer, passed 24 features into four machine learning models, calculated a weighted risk score, and issued a deployment decision — BLOCK. No human in the loop required."_

---

## DEMO STEP 2 — "Let's see what's happening under the hood"

_Talking point: "Reviewers sometimes want to see the reasoning, not just the verdict."_

**Command:**

```powershell
sc-guard scan test_contracts/ReentrancyVulnerable.sol --verbose
```

**What the audience sees:**

- Phase-by-phase progress indicators
- Feature extraction details (call depth, external calls, state changes...)
- Per-model confidence scores (e.g., Reentrancy: 0.91)
- Risk score breakdown
- Full recommendations

**Say:**

> _"The verbose flag reveals the five-phase pipeline: static analysis, feature extraction, ML prediction, risk scoring, and enforcement. Every number is traceable — this is an interpretable system, not a black box."_

---

## DEMO STEP 3 — "What about CI/CD? Machines need clean data"

_Talking point: "Integrating into a pipeline means the output needs to be machine-readable."_

**Command:**

```powershell
sc-guard scan test_contracts/AccessControlVulnerable.sol --json
```

**What the audience sees:**

- Clean JSON output with all vulnerability scores, risk score, decision
- Easy to parse in any pipeline or webhook

**Say:**

> _"The --json flag produces structured output for automated systems. A GitHub Action, a webhook, or a deployment script can consume this and halt a deployment without any human intervention."_

---

## DEMO STEP 4 — "Generating a professional security report"

_Talking point: "Developers need to share findings with non-technical stakeholders."_

**Command:**

```powershell
sc-guard scan test_contracts/ComplexVulnerable.sol --report html --verbose
```

**Then open the generated file:**

```powershell
# Get the report path from the output, then:
Start-Process "outputs\ComplexVulnerable_<timestamp>.html"
# Or open outputs/ folder and click the newest .html file
Invoke-Item outputs\
```

**What the audience sees:**

- Professional HTML report in the browser
- Executive summary with risk score prominently displayed
- Color-coded vulnerability breakdown table
- Per-vulnerability confidence scores
- Actionable recommendations

**Say:**

> _"This report can be sent to an audit committee, included in a pull request, or embedded in documentation. It's generated from a Jinja2 template and requires nothing beyond a browser to read."_

---

## DEMO STEP 5 — "What about programmatic access? REST API"

_Talking point: "Not every tool uses the CLI — IDEs, web apps, and services need an API."_

**In a SECOND terminal, start the API:**

```powershell
# Terminal 2 — start API server
cd C:\Users\prema\Desktop\Projects\sc-guard
.venv\Scripts\Activate.ps1
uvicorn api.main:app --reload --port 8000
```

**Back in Terminal 1, make an API call:**

```powershell
# Quick health check first
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health" -Method GET

# Full scan via API (send contract code as text)
$contractCode = Get-Content test_contracts/ReentrancyVulnerable.sol -Raw
$body = @{ contract_code = $contractCode; contract_name = "ReentrancyVulnerable" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scan" `
    -Method POST `
    -ContentType "application/json" `
    -Headers @{ "X-API-Key" = "dev-key-123" } `
    -Body $body
```

**What the audience sees:**

- JSON response with full vulnerability analysis
- HTTP 200 from a real REST endpoint

**Say:**

> _"The REST API accepts Solidity source code and returns the exact same analysis as the CLI. It has authentication via API key and rate limiting built in, so it's safe to expose in a multi-tenant environment. Any IDE plugin, web application, or deployment system can call this endpoint."_

> ⚠️ **Fallback if API fails:** Show [api/main.py](api/main.py) in VS Code and walk through the code. Say: _"Here's the FastAPI implementation — note the authentication middleware and rate limiting."_

---

## DEMO STEP 6 — "It's containerized — zero-config deployment"

_Talking point: "Docker means this runs identically on every machine."_

> ⚠️ Only do this step if Docker Desktop is running and image is built. Test beforehand.

**Commands:**

```powershell
# Build the image (show them the command, not necessarily wait live)
docker build -t sc-guard .

# Run a scan via Docker
docker run --rm -v ${PWD}/test_contracts:/contracts sc-guard sc-guard scan /contracts/ReentrancyVulnerable.sol
```

**Alternatively, show the Dockerfile:**

```powershell
# Open Dockerfile in terminal for audience
Get-Content Dockerfile
```

**Say:**

> _"The Dockerfile uses a multi-stage build. All dependencies — Python, Slither, solc — are pre-installed. No setup required on the target machine. You clone the repo, run docker build, and you're scanning contracts."_

---

## DEMO STEP 7 — "CI/CD: security baked into the development workflow"

_Talking point: "The best security tool is one developers never have to manually run."_

**Show the workflow file:**

```powershell
Get-Content .github\workflows\security-scan.yml
```

**Or open it in VS Code:**

```powershell
code .github\workflows\security-scan.yml
```

**Say:**

> _"This GitHub Actions workflow triggers automatically whenever a `.sol` file is pushed. It runs sc-guard, and if the risk score crosses the threshold, the build fails and the PR cannot be merged. Security is now a gate, not an afterthought."_

**Also mention (briefly):**

- `test.yml` — cross-platform pytest matrix (3 OS × 3 Python versions)
- `docker-build.yml` — pushes image to GitHub Container Registry on merge

---

## DEMO STEP 8 — "Comparing contracts: clean vs. vulnerable"

_Bonus step if time allows — very impactful for the audience_

**Show that sc-guard correctly distinguishes:**

```powershell
# Vulnerable contract — should BLOCK
sc-guard scan test_contracts/ReentrancyVulnerable.sol

# A simple safe contract (create one quickly or use a minimal example)
# Point out the ALLOW vs BLOCK difference
```

**Say:**

> _"Notice the decision changes. The system isn't just sounding alarm bells on everything — it's discriminating between patterns that are actually dangerous and those that are not."_

---

## CLOSING THE DEMO

```powershell
# Final command — show all output files generated during the demo
Get-ChildItem outputs\ | Select-Object Name, LastWriteTime | Format-Table
```

**Say:**

> _"In under 10 minutes, we've scanned multiple contracts, generated reports, called a REST API, and looked at containerization and CI/CD integration. That's the full sc-guard toolchain."_

---

## EMERGENCY FALLBACK PLAN

If the live environment breaks — stay calm, use these:

| Problem                       | Fallback                                                                  |
| ----------------------------- | ------------------------------------------------------------------------- |
| `sc-guard: command not found` | `python -m src.cli.main scan test_contracts/ReentrancyVulnerable.sol`     |
| Slither error / solc missing  | Show the JSON output from `report.json` in the root folder — pre-prepared |
| API won't start               | Open [api/main.py](api/main.py) in VS Code, walk through code structure   |
| Docker not available          | Open `Dockerfile` and explain multi-stage build conceptually              |
| Any Python error              | `pip install -r requirements.txt` then retry                              |
| No output folder              | `mkdir outputs` then retry                                                |

---

## ANTICIPATED QUESTIONS & ANSWERS

**Q: How accurate are the ML models?**

> _"The Random Forest models achieve ~80–85% accuracy on our test set drawn from the SmartBugs curated dataset — 143 real-world vulnerable contracts. The hybrid approach (static + ML) reduces false positives compared to static-only tools. We've included a MODEL_PERFORMANCE_SUMMARY.md with full metrics."_

**Q: What makes this different from Slither alone?**

> _"Slither is an excellent static analyzer, but it outputs a long list of potential issues with little guidance on severity or deployment impact. sc-guard adds ML-based confidence scoring, a weighted risk aggregation formula, and a concrete deployment decision. You get 'BLOCK this contract' not 'here are 47 possible issues.'"_

**Q: Why Random Forest and not a neural network?**

> _"Interpretability. In security tooling, developers need to understand why a contract is flagged, not just that it is. Random Forest gives us feature importance and is robust on small datasets. A neural network would need far more training data and would be a black box."_

**Q: Can it scan a whole project, not just one contract?**

> _"Not yet — that's a Phase 2 roadmap item. Multi-contract project scanning with cross-contract vulnerability detection is a significant architecturally interesting next step."_

**Q: What's the false positive rate?**

> _"It varies by vulnerability type. Our access control model has higher false positives on complex ownership patterns — we've added 8 specialized features to address that. It's an active area of improvement."_

**Q: Is the API production-ready?**

> _"It has authentication and rate limiting, which are the two most critical production concerns. For a production deployment you'd add TLS, persistent logging, and swap the in-memory model loading for a model server. The architecture supports that evolution."_

---

## DEMO CHECKLIST (check off before presenting)

- [ ] `.venv` activated
- [ ] `sc-guard --version` returns successfully
- [ ] `sc-guard scan test_contracts/ReentrancyVulnerable.sol` runs without error
- [ ] `--verbose` flag works and shows 5-phase pipeline
- [ ] `--json` flag produces valid JSON
- [ ] `--report html` generates a file in `outputs/`
- [ ] HTML report opens correctly in browser
- [ ] API server starts on port 8000 (`uvicorn api.main:app --reload --port 8000`)
- [ ] API health endpoint returns 200
- [ ] `.github/workflows/security-scan.yml` is visible and readable
- [ ] (Optional) Docker image builds successfully
- [ ] Browser tabs ready: `outputs/` folder, GitHub Actions tab
- [ ] Font size in terminal increased for visibility (Ctrl++ in terminal to zoom)
- [ ] PowerShell window maximized
