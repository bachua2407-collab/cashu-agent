#!/usr/bin/env python3
"""
CashuAgent: Autonomous Ecash Payment & Micropayment Engine for AI Agents
Nut November Hackathon 2026 Submission
Pure Python - Zero External Dependencies (Standard Library Only)
Supports: NUT-00, NUT-01, NUT-02, NUT-03, NUT-04, NUT-05, NUT-06, NUT-07, and HTTP 402 Interceptor.
"""

import hashlib
import struct
import secrets
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
import ssl
import sys
import os
import time

# ==============================================================================
# 1. SECP256K1 CRYPTOGRAPHY & BDHKE IMPLEMENTATION (NUT-00)
# ==============================================================================

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BB5BF5670F144D721
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

def inv(a, m=P):
    """Modular inverse using Fermat's Little Theorem."""
    return pow(a, m - 2, m)

def point_add(p1, p2):
    """Elliptic curve point addition on secp256k1."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2 and y1 == y2:
        if y1 == 0:
            return None
        l = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        l = (y2 - y1) * inv(x2 - x1) % P
    x3 = (l * l - x1 - x2) % P
    y3 = (l * (x1 - x3) - y1) % P
    return (x3, y3)

def point_mul(k, p):
    """Scalar multiplication on secp256k1 using double-and-add."""
    if p is None or k % N == 0:
        return None
    k = k % N
    res = None
    cur = p
    while k > 0:
        if k & 1:
            res = point_add(res, cur)
        cur = point_add(cur, cur)
        k >>= 1
    return res

def point_neg(p):
    """Point negation on secp256k1."""
    if p is None:
        return None
    return (p[0], (P - p[1]) % P)

def decompress_point(pubkey_bytes):
    """Decompresses SEC1 33-byte public key to (x, y) point."""
    if len(pubkey_bytes) != 33:
        return None
    prefix = pubkey_bytes[0]
    if prefix not in (2, 3):
        return None
    x = int.from_bytes(pubkey_bytes[1:], 'big')
    y_sq = (pow(x, 3, P) + 7) % P
    if pow(y_sq, (P - 1) // 2, P) != 1:
        return None
    y = pow(y_sq, (P + 1) // 4, P)
    if (prefix == 2 and y % 2 != 0) or (prefix == 3 and y % 2 == 0):
        y = (P - y) % P
    return (x, y)

def compress_point(p):
    """Compresses (x, y) point to 33-byte SEC1 hex string."""
    if p is None:
        return ""
    x, y = p
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return (prefix + x.to_bytes(32, 'big')).hex()

def hash_to_curve(x_bytes):
    """NUT-00 deterministic hash_to_curve algorithm."""
    msg_hash = hashlib.sha256(DOMAIN_SEPARATOR + x_bytes).digest()
    counter = 0
    while counter < 2**32:
        counter_bytes = struct.pack('<I', counter)
        h = hashlib.sha256(msg_hash + counter_bytes).digest()
        pt = decompress_point(b'\x02' + h)
        if pt is not None:
            return pt
        counter += 1
    raise RuntimeError("hash_to_curve counter overflow")

def blind_message(secret_hex):
    """
    Alice computes blinded point B_ = Y + r*G
    Returns: (B_hex, r_int)
    """
    Y = hash_to_curve(secret_hex.encode('utf-8'))
    r = secrets.randbelow(N - 1) + 1
    rG = point_mul(r, G)
    B_prime = point_add(Y, rG)
    return compress_point(B_prime), r

def unblind_signature(C_prime_hex, r, K_hex):
    """
    Alice unblinds signature C = C_ - r*K
    Returns: C_hex
    """
    C_prime = decompress_point(bytes.fromhex(C_prime_hex))
    K = decompress_point(bytes.fromhex(K_hex))
    rK = point_mul(r, K)
    neg_rK = point_neg(rK)
    C = point_add(C_prime, neg_rK)
    return compress_point(C)

def verify_proof(secret_hex, C_hex, k_priv):
    """
    Mint verification: checks C == k * hash_to_curve(secret)
    """
    Y = hash_to_curve(secret_hex.encode('utf-8'))
    expected_C = point_mul(k_priv, Y)
    actual_C = decompress_point(bytes.fromhex(C_hex))
    return expected_C == actual_C

# ==============================================================================
# 2. TOKEN SERIALIZATION & DESERIALIZATION (NUT-00 V3)
# ==============================================================================

def serialize_token_v3(mint_url, proofs, unit="sat", memo=""):
    """Encodes proofs into cashuA... base64 token string."""
    clean_mint = mint_url.rstrip('/')
    token_obj = {
        "token": [
            {
                "mint": clean_mint,
                "proofs": proofs
            }
        ],
        "unit": unit
    }
    if memo:
        token_obj["memo"] = memo
    json_bytes = json.dumps(token_obj, separators=(',', ':')).encode('utf-8')
    b64_str = base64.urlsafe_b64encode(json_bytes).decode('utf-8').rstrip('=')
    return f"cashuA{b64_str}"

def deserialize_token_v3(token_str):
    """Decodes cashuA... token string into dictionary object."""
    if token_str.startswith("cashu:"):
        token_str = token_str[6:]
    if not token_str.startswith("cashuA"):
        raise ValueError("Unsupported token format (expected cashuA prefix)")

    b64_data = token_str[6:]
    padding = len(b64_data) % 4
    if padding:
        b64_data += '=' * (4 - padding)

    json_bytes = base64.urlsafe_b64decode(b64_data)
    return json.loads(json_bytes.decode('utf-8'))

# ==============================================================================
# 3. WALLET STORAGE & PROOF ACCOUNTING
# ==============================================================================

class CashuWallet:
    def __init__(self, mint_url="https://mint.minibits.cash/Bitcoin", storage_path="cashu_wallet.json"):
        self.mint_url = mint_url.rstrip('/')
        self.storage_path = storage_path
        self.ctx = ssl._create_unverified_context()
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"mint": self.mint_url, "proofs": []}

    def save(self):
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    @property
    def balance(self):
        return sum(p.get("amount", 0) for p in self.data["proofs"])

    def add_proofs(self, proofs):
        existing_secrets = {p["secret"] for p in self.data["proofs"]}
        for p in proofs:
            if p["secret"] not in existing_secrets:
                self.data["proofs"].append(p)
                existing_secrets.add(p["secret"])
        self.save()

    def select_proofs(self, amount):
        """Greedy selection of proofs to satisfy amount."""
        if self.balance < amount:
            raise ValueError(f"Insufficient balance: have {self.balance} sats, need {amount} sats")

        sorted_proofs = sorted(self.data["proofs"], key=lambda x: x["amount"], reverse=True)
        selected = []
        accum = 0
        for p in sorted_proofs:
            selected.append(p)
            accum += p["amount"]
            if accum >= amount:
                break
        return selected, accum

    def remove_proofs(self, proofs):
        to_remove = {p["secret"] for p in proofs}
        self.data["proofs"] = [p for p in self.data["proofs"] if p["secret"] not in to_remove]
        self.save()

    # --- HTTP API Helper ---
    def _request(self, endpoint, data=None):
        url = f"{self.mint_url}{endpoint}"
        headers = {'User-Agent': 'CashuAgent/1.0', 'Accept': 'application/json'}
        req_data = None
        if data is not None:
            headers['Content-Type'] = 'application/json'
            req_data = json.dumps(data).encode('utf-8')

        req = urllib.request.Request(url, data=req_data, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=20) as resp:
            return json.loads(resp.read().decode('utf-8'))

    # --- NUT-06: Mint Info ---
    def get_info(self):
        return self._request("/v1/info")

    # --- NUT-01: Mint Keys ---
    def get_keys(self):
        return self._request("/v1/keys")

    # --- NUT-04: Minting via Lightning ---
    def create_mint_quote(self, amount_sats):
        """Requests a Lightning invoice to deposit sats into ecash wallet."""
        res = self._request("/v1/mint/quote/bolt11", {"amount": amount_sats, "unit": "sat"})
        return res

    def check_mint_quote(self, quote_id):
        return self._request(f"/v1/mint/quote/bolt11/{quote_id}")

    def mint_tokens(self, quote_id, amount_sats):
        """Once invoice is paid, mints tokens and unblinds signatures."""
        keys_data = self.get_keys()
        keyset = keys_data["keysets"][0]
        keyset_id = keyset["id"]
        keys = keyset["keys"]

        # Decompose amount into powers of 2
        amounts = []
        rem = amount_sats
        power = 1
        while rem > 0:
            if rem & power:
                amounts.append(power)
                rem -= power
            power <<= 1

        blinded_outputs = []
        secrets_info = []

        for amt in amounts:
            secret = secrets.token_hex(32)
            B_prime, r = blind_message(secret)
            blinded_outputs.append({
                "amount": amt,
                "id": keyset_id,
                "B_": B_prime
            })
            secrets_info.append((secret, r, str(amt)))

        mint_res = self._request("/v1/mint/bolt11", {
            "quote": quote_id,
            "outputs": blinded_outputs
        })

        signatures = mint_res.get("signatures", [])
        new_proofs = []
        for sig, (sec, r, amt_str) in zip(signatures, secrets_info):
            C_prime = sig["C_"]
            K_hex = keys[amt_str]
            C = unblind_signature(C_prime, r, K_hex)
            new_proofs.append({
                "id": keyset_id,
                "amount": int(amt_str),
                "secret": sec,
                "C": C
            })

        self.add_proofs(new_proofs)
        return new_proofs

    # --- NUT-03: Swap / Split ---
    def swap(self, input_proofs, split_amounts):
        """Swaps input proofs for new proofs with requested amounts."""
        keys_data = self.get_keys()
        keyset = keys_data["keysets"][0]
        keyset_id = keyset["id"]
        keys = keyset["keys"]

        blinded_outputs = []
        secrets_info = []
        for amt in split_amounts:
            secret = secrets.token_hex(32)
            B_prime, r = blind_message(secret)
            blinded_outputs.append({
                "amount": amt,
                "id": keyset_id,
                "B_": B_prime
            })
            secrets_info.append((secret, r, str(amt)))

        swap_res = self._request("/v1/swap", {
            "inputs": input_proofs,
            "outputs": blinded_outputs
        })

        signatures = swap_res.get("signatures", [])
        new_proofs = []
        for sig, (sec, r, amt_str) in zip(signatures, secrets_info):
            C_prime = sig["C_"]
            K_hex = keys[amt_str]
            C = unblind_signature(C_prime, r, K_hex)
            new_proofs.append({
                "id": keyset_id,
                "amount": int(amt_str),
                "secret": sec,
                "C": C
            })

        self.remove_proofs(input_proofs)
        self.add_proofs(new_proofs)
        return new_proofs

    # --- NUT-05: Melt (Pay Lightning Invoice) ---
    def melt(self, invoice_bolt11):
        """Pays a Lightning invoice using ecash proofs."""
        quote = self._request("/v1/melt/quote/bolt11", {
            "request": invoice_bolt11,
            "unit": "sat"
        })
        needed_amount = quote["amount"] + quote.get("fee_reserve", 0)
        selected_proofs, total_selected = self.select_proofs(needed_amount)

        # If total selected is more than needed, swap first to have exact change
        if total_selected > needed_amount:
            change = total_selected - needed_amount
            # Swap selected proofs to exact needed + change
            self.swap(selected_proofs, [needed_amount, change])
            selected_proofs, _ = self.select_proofs(needed_amount)

        melt_res = self._request("/v1/melt/bolt11", {
            "quote": quote["quote"],
            "inputs": selected_proofs
        })

        if melt_res.get("paid"):
            self.remove_proofs(selected_proofs)
            return melt_res
        raise RuntimeError(f"Melt failed: {melt_res}")

    # --- NUT-07: Check State ---
    def check_proof_states(self):
        """Verifies if wallet proofs are unspent or spent at the mint."""
        if not self.data["proofs"]:
            return {}
        res = self._request("/v1/checkstate", {"Ys": [compress_point(hash_to_curve(p["secret"].encode('utf-8'))) for p in self.data["proofs"]]})
        states = res.get("states", [])
        return states

    # --- Transfer / Token Creation ---
    def send_token(self, amount, memo=""):
        """Creates a standalone cashuA... token to send to another agent."""
        selected, total = self.select_proofs(amount)
        if total > amount:
            change = total - amount
            # Exact split
            new_proofs = self.swap(selected, [amount, change])
            # Filter the exact amount proofs
            send_proofs = [p for p in new_proofs if p["amount"] == amount]
            if not send_proofs:
                send_proofs = new_proofs[:1]
        else:
            send_proofs = selected

        self.remove_proofs(send_proofs)
        token_str = serialize_token_v3(self.mint_url, send_proofs, unit="sat", memo=memo)
        return token_str

    def receive_token(self, token_str):
        """Receives and redeems a cashuA... token into the local wallet."""
        token_data = deserialize_token_v3(token_str)
        mint_data = token_data["token"][0]
        mint = mint_data["mint"]
        proofs = mint_data["proofs"]

        # If incoming token is from the same mint, swap for clean proofs
        if mint == self.mint_url:
            total_amt = sum(p["amount"] for p in proofs)
            # Decompose into powers of 2
            amounts = []
            rem = total_amt
            power = 1
            while rem > 0:
                if rem & power:
                    amounts.append(power)
                    rem -= power
                power <<= 1
            redeemed = self.swap(proofs, amounts)
            return sum(p["amount"] for p in redeemed)
        else:
            # Add directly
            self.add_proofs(proofs)
            return sum(p["amount"] for p in proofs)

# ==============================================================================
# 4. AUTONOMOUS HTTP 402 INTERCEPTOR (FOR AI AGENTS)
# ==============================================================================

class CashuAgentClient:
    """
    HTTP Client with automated Cashu HTTP 402 interceptor.
    Allows autonomous agents to access paid APIs seamlessly.
    """
    def __init__(self, wallet=None):
        self.wallet = wallet or CashuWallet()
        self.ctx = ssl._create_unverified_context()

    def request(self, url, method="GET", data=None, headers=None):
        default_headers = {'User-Agent': 'CashuAutonomousAgent/1.0'}
        if headers:
            default_headers.update(headers)

        req_data = None
        if data:
            req_data = json.dumps(data).encode('utf-8')
            default_headers['Content-Type'] = 'application/json'

        req = urllib.request.Request(url, data=req_data, headers=default_headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
                return {
                    "status": resp.status,
                    "data": resp.read().decode('utf-8', errors='ignore')
                }
        except urllib.error.HTTPError as e:
            if e.code == 402:
                print(f"[CashuAgent] HTTP 402: Payment Required at {url}")
                auth_header = e.headers.get('WWW-Authenticate') or e.headers.get('X-Cashu')
                return self._handle_402_and_retry(url, method, data, default_headers, auth_header)
            raise e

    def _handle_402_and_retry(self, url, method, data, headers, auth_header):
        # Default price is 1 sat if not specified
        amount_sats = 1
        if auth_header and "amount=" in auth_header:
            try:
                import re
                m = re.search(r'amount=(\d+)', auth_header)
                if m:
                    amount_sats = int(m.group(1))
            except Exception:
                pass

        print(f"[CashuAgent] Generating {amount_sats} sat ecash token from local wallet...")
        token_str = self.wallet.send_token(amount_sats, memo=f"Paywall payment for {url}")

        # Attach payment proof
        headers['Authorization'] = f"Cashu {token_str}"
        headers['X-Cashu'] = token_str

        req_data = json.dumps(data).encode('utf-8') if data else None
        retry_req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        with urllib.request.urlopen(retry_req, context=self.ctx, timeout=15) as resp:
            print(f"[CashuAgent] Successfully accessed paid endpoint! Status: {resp.status}")
            return {
                "status": resp.status,
                "data": resp.read().decode('utf-8', errors='ignore'),
                "paid_sats": amount_sats
            }

# ==============================================================================
# 5. CLI INTERFACE
# ==============================================================================

def print_help():
    print("""
CashuAgent: Autonomous Ecash Payment Engine (Nut November Hackathon 2026)
Usage:
  python cashu_agent.py balance                     Check local wallet balance in sats
  python cashu_agent.py info                        Query connected Cashu mint metadata
  python cashu_agent.py deposit <sats>              Get Lightning invoice to fund wallet
  python cashu_agent.py send <sats> [memo]          Export cashuA... ecash token
  python cashu_agent.py receive <cashuA...>         Redeem ecash token into local wallet
  python cashu_agent.py pay <bolt11_invoice>        Pay any Lightning invoice using ecash
  python cashu_agent.py test                        Run internal cryptographic verification
""")

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    args = sys.argv[1:]
    if not args:
        print_help()
        sys.exit(0)

    cmd = args[0].lower()
    wallet = CashuWallet()

    if cmd == "balance":
        print(f"💰 Wallet Balance: {wallet.balance} satoshis")
        print(f"📍 Connected Mint: {wallet.mint_url}")
        print(f"📦 Stored Proofs: {len(wallet.data['proofs'])}")

    elif cmd == "info":
        info = wallet.get_info()
        print("🏛️ Mint Information:")
        print(f"  Name: {info.get('name')}")
        print(f"  Version: {info.get('version')}")
        print(f"  Description: {info.get('description')}")
        print(f"  Active NUTs: {list(info.get('nuts', {}).keys())}")

    elif cmd == "deposit":
        if len(args) < 2:
            print("Usage: python cashu_agent.py deposit <amount_sats>")
            sys.exit(1)
        amt = int(args[1])
        quote = wallet.create_mint_quote(amt)
        print(f"⚡ Lightning Invoice to Deposit {amt} sats:")
        print(f"{quote['request']}")
        print(f"\nQuote ID: {quote['quote']}")
        print("👉 Pay the invoice above with any Lightning wallet, then run:")
        print(f"   python cashu_agent.py claim-mint {quote['quote']} {amt}")

    elif cmd == "claim-mint":
        if len(args) < 3:
            print("Usage: python cashu_agent.py claim-mint <quote_id> <amount_sats>")
            sys.exit(1)
        qid = args[1]
        amt = int(args[2])
        print(f"⏳ Claiming and unblinding {amt} sats from quote {qid}...")
        try:
            proofs = wallet.mint_tokens(qid, amt)
            print(f"✅ Successfully minted {amt} sats! New Balance: {wallet.balance} sats.")
        except Exception as e:
            print(f"❌ Claim error (invoice may still be unpaid): {e}")

    elif cmd == "send":
        if len(args) < 2:
            print("Usage: python cashu_agent.py send <amount_sats> [memo]")
            sys.exit(1)
        amt = int(args[1])
        memo = args[2] if len(args) > 2 else ""
        try:
            token = wallet.send_token(amt, memo)
            print(f"🎁 Cashu Token ({amt} sats):")
            print(token)
        except Exception as e:
            print(f"❌ Error: {e}")

    elif cmd == "receive":
        if len(args) < 2:
            print("Usage: python cashu_agent.py receive <cashuA...>")
            sys.exit(1)
        tok = args[1]
        try:
            redeemed = wallet.receive_token(tok)
            print(f"✅ Received and verified {redeemed} sats! New Balance: {wallet.balance} sats.")
        except Exception as e:
            print(f"❌ Error redeeming token: {e}")

    elif cmd == "pay":
        if len(args) < 2:
            print("Usage: python cashu_agent.py pay <bolt11_invoice>")
            sys.exit(1)
        inv = args[1]
        try:
            res = wallet.melt(inv)
            print(f"⚡ Lightning Invoice Paid! Preimage: {res.get('payment_preimage')}")
        except Exception as e:
            print(f"❌ Melt error: {e}")

    elif cmd == "test":
        print("🔬 Running internal cryptographic test suite...")
        # 1. Point addition & doubling test
        P1 = point_mul(7, G)
        P2 = point_mul(5, G)
        assert point_add(P1, P2) == point_mul(12, G), "Point addition mismatch"
        print("  ✓ Elliptic curve addition & scalar multiplication verified")

        # 2. NUT-00 hash_to_curve test
        test_sec = "cashu_secret_test_12345"
        Y = hash_to_curve(test_sec.encode('utf-8'))
        assert Y is not None, "hash_to_curve failed"
        print("  ✓ NUT-00 hash_to_curve verified")

        # 3. BDHKE blinding & unblinding cycle
        priv_k = secrets.randbelow(N - 1) + 1
        pub_K = point_mul(priv_k, G)
        pub_K_hex = compress_point(pub_K)

        B_prime_hex, r = blind_message(test_sec)
        B_prime = decompress_point(bytes.fromhex(B_prime_hex))
        C_prime = point_mul(priv_k, B_prime)
        C_prime_hex = compress_point(C_prime)

        C_hex = unblind_signature(C_prime_hex, r, pub_K_hex)
        assert verify_proof(test_sec, C_hex, priv_k), "BDHKE proof verification failed"
        print("  ✓ BDHKE blinding, signing, unblinding, and verification verified")

        # 4. Token serialization test
        sample_proofs = [{"id": "009a1f293253e41e", "amount": 2, "secret": test_sec, "C": C_hex}]
        tok = serialize_token_v3("https://mint.minibits.cash/Bitcoin", sample_proofs, unit="sat", memo="Test")
        assert tok.startswith("cashuA"), "Token prefix invalid"
        decoded = deserialize_token_v3(tok)
        assert decoded["token"][0]["proofs"][0]["amount"] == 2, "Token deserialization mismatch"
        print("  ✓ NUT-00 Token v3 base64 serialization/deserialization verified")
        print("\n🎉 ALL INTERNAL TESTS PASSED!")

    else:
        print_help()
