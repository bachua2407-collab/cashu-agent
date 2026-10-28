#!/usr/bin/env python3
"""
CashuAgent Example: Autonomous HTTP 402 Interceptor for AI Agents
Demonstrates how an AI agent uses zero-dependency ecash to pay for real-time intelligence.
"""

from cashu_agent import CashuAgentClient, CashuWallet

def main():
    print("🌰 Initializing CashuAgent for Autonomous AI Payment...")
    wallet = CashuWallet()
    print(f"  Target Mint: {wallet.mint_url}")
    print(f"  Wallet Balance: {wallet.get_balance()} sats")

    client = CashuAgentClient(wallet=wallet)

    print("\nSimulating agent querying paid endpoint...")
    print("In production, when an endpoint returns HTTP 402 (Payment Required) with Cashu headers:")
    print("  1. The client intercepts status 402")
    print("  2. Selects proofs matching required amount")
    print("  3. Encodes NUT-00 Token v3 (cashuA...)")
    print("  4. Re-sends request with Authorization: Cashu <token>")
    print("  5. Receives payload and continues execution autonomously.")

if __name__ == "__main__":
    main()
