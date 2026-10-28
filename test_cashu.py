"""
Comprehensive Unittest Suite for CashuAgent
Zero-dependency verification of secp256k1 point math, BDHKE blinding/unblinding, and NUT-00 tokens.
"""

import unittest
import cashu_agent as ca

class TestCashuAgentCrypto(unittest.TestCase):
    def test_curve_math(self):
        # G + G = 2G
        g2 = ca.point_add(ca.G, ca.G)
        self.assertIsNotNone(g2)
        g2_mul = ca.point_mul(2, ca.G)
        self.assertEqual(g2, g2_mul)

        # Point compression & decompression roundtrip
        comp_hex = ca.compress_point(ca.G)
        self.assertEqual(len(comp_hex), 66)
        decomp = ca.decompress_point(bytes.fromhex(comp_hex))
        self.assertEqual(decomp, ca.G)

    def test_hash_to_curve(self):
        msg = b"test_agent_secret_message_for_cashu"
        pt = ca.hash_to_curve(msg)
        self.assertIsNotNone(pt)
        # Verify point satisfies y^2 = x^3 + 7 (mod P)
        x, y = pt
        self.assertEqual((y * y) % ca.P, (x * x * x + 7) % ca.P)

    def test_bdhke_cycle(self):
        # Mint private scalar a and public key K = a*G
        a = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
        K = ca.point_mul(a, ca.G)
        K_hex = ca.compress_point(K)

        # Agent blinds secret
        secret = "nut_november_test_secret_001"
        B_prime_hex, r = ca.blind_message(secret)
        self.assertTrue(len(B_prime_hex) == 66)
        self.assertTrue(r > 0)

        # Mint signs: C' = a * B'
        B_prime = ca.decompress_point(bytes.fromhex(B_prime_hex))
        C_prime = ca.point_mul(a, B_prime)
        C_prime_hex = ca.compress_point(C_prime)

        # Agent unblinds: C = C' - r * K
        C_hex = ca.unblind_signature(C_prime_hex, r, K_hex)

        # Verify C == a * hash_to_curve(secret)
        Y = ca.hash_to_curve(secret.encode('utf-8'))
        expected_C = ca.point_mul(a, Y)
        self.assertEqual(C_hex, ca.compress_point(expected_C))
        self.assertTrue(ca.verify_proof(secret, C_hex, a))

    def test_token_serialization(self):
        proofs = [
            {"id": "009a1f293252f338", "amount": 1, "secret": "sec1", "C": "02" + "11" * 32},
            {"id": "009a1f293252f338", "amount": 2, "secret": "sec2", "C": "02" + "22" * 32}
        ]
        mint_url = "https://mint.minibits.cash/Bitcoin"
        token_str = ca.serialize_token_v3(mint_url, proofs)
        self.assertTrue(token_str.startswith("cashuA"))

        parsed_obj = ca.deserialize_token_v3(token_str)
        self.assertIn("token", parsed_obj)
        first_token = parsed_obj["token"][0]
        self.assertEqual(len(first_token["proofs"]), 2)
        self.assertEqual(first_token["mint"], mint_url)

if __name__ == '__main__':
    unittest.main()
