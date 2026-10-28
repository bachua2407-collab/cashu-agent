# 🌰 CashuAgent: Autonomous Ecash Payment Engine for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Nut November 2026](https://img.shields.io/badge/Hackathon-Nut_November_2026-orange.svg)](https://nutnovember.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)]()

> **Submission for Nut November Hackathon 2026** (`nutnovember.org`)  
> **Track:** Tools, Wallets & Agent Infrastructure  
> **Prize Pool:** 500,000 Satoshis  
> **Core Requirement:** Pure Python standard library — **Zero external dependencies (No pip install required)**  
> **Bitcoin Payout Address:** `bc1qrjc93peuatns3n5snr0f8nsvmlnt0fth684a5g`

---

## 🚀 Problem Statement

Autonomous AI agents (such as Claude Code, AutoGPT, LangChain agents, and MCP servers) are currently bottlenecked by legacy financial rails:
1. **No Bank Accounts or KYC:** Software agents cannot open fiat accounts, pass KYC selfie checks, or obtain credit cards.
2. **Heavy Dependencies:** Existing crypto libraries require C extensions (`libsecp256k1`, `cryptography`, `pydantic`), creating build failures in containerized or minimal runtime environments.
3. **High Latency of On-Chain:** Paying 1–5 sats per LLM prompt or API call on Bitcoin Mainnet is unviable due to block times and miner fee minimums.

---

## 💡 The Solution: CashuAgent

**CashuAgent** is a zero-dependency Python engine implementing the **Cashu Chaumian Ecash Protocol (NUT-00 to NUT-07)** tailored specifically for autonomous AI agents.

With CashuAgent:
- **Instant Micro-Settlement:** Agents pay and receive 1–10 satoshis instantly with zero network fees.
- **Unlinkable Chaumian Privacy:** Blind Diffie-Hellman Key Exchange (BDHKE) ensures neither the mint nor the API vendor can correlate payments to agent identity.
- **Automated HTTP 402 Interceptor:** When an agent queries an API and receives an `HTTP 402: Payment Required` status, CashuAgent automatically cuts an exact ecash token from its local wallet, attaches `Authorization: Cashu <token>`, and retries seamlessly without human intervention.
- **Universal Portability:** Runs out-of-the-box on any machine with Python 3.8+ (Windows, Linux, macOS, Raspberry Pi, Docker, AWS Lambda).

---

## 🛠️ Architecture & Protocol Flow

```
[ AI Agent / MCP Server ]                          [ Paid Data / LLM API ]
          |                                                   |
          |---- (1) GET /v1/intel --------------------------->|
          |                                                   |
          |<--- (2) HTTP 402 Payment Required ----------------|
          |         WWW-Authenticate: Cashu amount=1 sat      |
          |                                                   |
   [ CashuAgent Engine ]                                      |
   - Selects / splits proof (NUT-03)                          |
   - Serializes cashuA... token (NUT-00)                      |
          |                                                   |
          |---- (3) GET /v1/intel --------------------------->|
          |         Authorization: Cashu cashuAeyJwcm...      |
          |                                                   |
          |<--- (4) HTTP 200 OK + Real-time Payload ----------|
```

---

## 📐 NUT Standards Implemented

| NUT | Specification | Status in CashuAgent |
|---|---|---|
| **NUT-00** | Cryptography & Token Models (secp256k1 point math, `hash_to_curve`, BDHKE, Token v3 `cashuA...`) | ✅ Fully Implemented (Pure Python) |
| **NUT-01** | Mint Public Keys (`GET /v1/keys`) | ✅ Fully Implemented |
| **NUT-02** | Keysets & Fee Structures (`GET /v1/keysets`) | ✅ Fully Implemented |
| **NUT-03** | Swap & Split Tokens (`POST /v1/swap`) | ✅ Fully Implemented |
| **NUT-04** | Minting via Lightning (`POST /v1/mint/quote/bolt11`, `/v1/mint/bolt11`) | ✅ Fully Implemented |
| **NUT-05** | Melting to Lightning (`POST /v1/melt/quote/bolt11`, `/v1/melt/bolt11`) | ✅ Fully Implemented |
| **NUT-06** | Mint Information (`GET /v1/info`) | ✅ Fully Implemented |
| **NUT-07** | Proof State Verification (`POST /v1/checkstate`) | ✅ Fully Implemented |
| **HTTP 402** | Automated Client Interceptor & Micro-Paywall Server | ✅ Included in Core Engine |

---

## ⚡ Quickstart

### 1. Run Cryptographic Verification
Verify the pure-Python secp256k1 arithmetic and BDHKE blinding cycle:
```bash
python cashu_agent.py test
```
*Output:*
```text
🔬 Running internal cryptographic test suite...
  ✓ Elliptic curve addition & scalar multiplication verified
  ✓ NUT-00 hash_to_curve verified
  ✓ BDHKE blinding, signing, unblinding, and verification verified
  ✓ NUT-00 Token v3 base64 serialization/deserialization verified

🎉 ALL INTERNAL TESTS PASSED!
```

### 2. Check Mint & Wallet Status
```bash
python cashu_agent.py info
python cashu_agent.py balance
```

### 3. Fund Wallet via Lightning Deposit (NUT-04)
```bash
python cashu_agent.py deposit 100
```
This generates a Bolt11 Lightning invoice from the mint. Once paid via any Lightning wallet, claim the unblinded ecash proofs:
```bash
python cashu_agent.py claim-mint <quote_id> 100
```

### 4. Create an Ecash Token (NUT-00 Send)
```bash
python cashu_agent.py send 5 "Payment for AI Inference"
```
Produces an instant `cashuAeyJw...` token ready to paste in Nostr, chat, or API headers.

### 5. Melt Ecash Back to Lightning (NUT-05 Pay)
```bash
python cashu_agent.py pay <bolt11_invoice>
```

---

## 🤖 Integration for Python AI Agents

```python
from cashu_agent import CashuAgentClient

# Create an autonomous agent client with an ecash wallet
client = CashuAgentClient()

# Query an API endpoint that requires 1 satoshi:
# The client automatically detects HTTP 402, generates the token, pays, and returns the data!
response = client.request("https://api.example.com/ai/realtime-intel")
print("Response data:", response["data"])
print("Sats paid:", response.get("paid_sats", 0))
```

---

## 🏆 Submission Details for Nut November 2026

- **Project:** CashuAgent (`cashu_agent.py`)
- **Hackathon:** [Nut November](https://nutnovember.org/) (Nov 1–27, 2026)
- **Target Category:** Tools, Micro-services & First-Time Contributor Award
- **Prize Sats Recipient:** `bc1qrjc93peuatns3n5snr0f8nsvmlnt0fth684a5g`
- **License:** MIT License
