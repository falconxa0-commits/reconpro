"""Corpus-based secret-detection quality tests.

Two labeled corpora drive the quality bar:

POSITIVE  — syntactically valid (but fake) secrets that MUST be detected.
           Zero false negatives allowed: a missed secret is the worst
           failure mode of a scanner.

NEGATIVE  — lookalikes, placeholders, prose, hashes, and public material
           that MUST NOT be flagged. Zero false positives targeted
           (any FP here gets triaged: either fix the pattern or move the
           sample to a documented accepted-FP list with justification).

The corpus is versioned with the code: any pattern change must keep both
sides green.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.security import detect_secrets_in_text

# ═══════════════════════════════════════════════════════════════════════
# POSITIVE corpus — must detect (all values are FAKE, never valid creds)
# ═══════════════════════════════════════════════════════════════════════

POSITIVES = {
    "aws_access_key": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "aws_temporary_key": "creds = ASIAIOSFODNN7EXAMPLE",
    "aws_secret_key": "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1",
    "github_pat": "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "github_oauth": "auth = gho_16C7e42F292c6912E7710c838347Ae178B4aA",
    "github_server": "conf = ghs_16C7e42F292c6912E7710c838347Ae178B4aB",
    "github_finegrained": "token: github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz",
    "gitlab_pat": "GL_TOKEN=glpat-AbCdEfGhIjKlMnOpQrStUv",
    "openai_key": "client.api_key = 'sk-proj-4abc9dEfGhIjKlMnOpQrStUvWxYz0123456789abcdef'",
    "openai_legacy": "key = sk-4abc9dEfGhIjKlMnOpQrStUvWxYz0123456789abcdef",
    "anthropic_key": "ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz123",
    "private_key_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "private_key_ec": "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE\n-----END EC PRIVATE KEY-----",
    "private_pkcs8": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
    "private_key_openssh": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
    "db_url_postgres": "DATABASE_URL=postgres://admin:S3cr3tP@ss@db.internal:5432/prod",
    "db_url_mysql": "dsn = mysql://root:hunter2@10.0.0.4:3306/shop",
    "db_url_mongo": "uri = mongodb+srv://svc:passw0rd@cluster0.example.net/db",
    "db_url_redis": "REDIS_URL=redis://default:Ch4ngeMe@redis.internal:6379/0",
    "password_in_url": "fetch https://user:hunter2@example.com/data",
    "jwt": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THs",
    "vault_token": "VAULT_TOKEN=hvs.CAESIJ_AbCdEfGhIjKlMnOpQrStUvWxYz12345",
}

# ═══════════════════════════════════════════════════════════════════════
# NEGATIVE corpus — must NOT flag
# ═══════════════════════════════════════════════════════════════════════

NEGATIVES = {
    "prose_asia": "We operate in the ASIA region with multiple PoPs.",
    "short_aws_like": "key AKIA1234 is too short to be real",
    "docs_placeholder": 'api_key = "YOUR_API_KEY_HERE"  # set your key',
    "docs_placeholder2": 'token: "<insert-token>"',
    "placeholder_changeme": "password = changeme",
    "json_key_value": '{"key": "thisIsALongValueThatIsNotSecret1234"}',
    "monkey_trap": "monkey=someLongValueThatWouldMatchOldBareKeyPattern",
    "sha256_hex": "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "uuid": "id = 123e4567-e89b-12d3-a456-426614174000",
    "base64_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    "url_no_creds": "https://example.com/docs?page=2&lang=en",
    "prose_secret_word": "the secret of good architecture is boring code",
    "sk_word": "we went sk-ipping stones by the lake",
    "ci_var_name": "GITHUB_TOKEN_REF in the workflow refers to docs",
    "prose_github": "commit with ghp_ mentioned in the README",
}


class TestPositiveCorpus(unittest.TestCase):
    """Every entry must be detected — zero false negatives."""

    def test_all_positive_samples_detected(self):
        missed = []
        for name, sample in POSITIVES.items():
            with self.subTest(sample=name):
                found = detect_secrets_in_text(sample)
                if not found:
                    missed.append(name)
        self.assertEqual(missed, [], f"FALSE NEGATIVES: {missed}")

    def test_specific_type_mappings(self):
        expectations = {
            "aws_access_key": "aws_key",
            "aws_temporary_key": "aws_key_temporary",
            "aws_secret_key": "aws_secret_access_key",
            "github_pat": "github_token",
            "github_oauth": "github_token_variant",
            "github_server": "github_token_variant",
            "gitlab_pat": "gitlab_token",
            "private_key_rsa": "private_key_rsa",
            "private_key_ec": "private_key_ec",
            "private_pkcs8": "private_key_generic",
            "private_key_openssh": "private_key_openssh",
            "db_url_postgres": "db_connection_string",
            "jwt": "jwt_token",
        }
        for sample_name, expected_type in expectations.items():
            with self.subTest(sample=sample_name, type=expected_type):
                found = detect_secrets_in_text(POSITIVES[sample_name])
                types = {f["type"] for f in found}
                self.assertIn(expected_type, types)

    def test_openai_and_anthropic_detected(self):
        for name in ("openai_key", "openai_legacy", "anthropic_key"):
            with self.subTest(sample=name):
                found = detect_secrets_in_text(POSITIVES[name])
                types = {f["type"] for f in found}
                self.assertTrue(
                    types & {"openai_api_key", "anthropic_api_key", "generic_api_key"},
                    f"{name} not detected: {types}",
                )


class TestNegativeCorpus(unittest.TestCase):
    """No entry may be flagged — zero false positives (documented exceptions only)."""

    def test_no_false_positives(self):
        accepted_fps = {
            # "prose_github" mentions ghp_ but is too short to match the
            # 36-char pattern — verify that claim below instead.
        }
        flagged = []
        for name, sample in NEGATIVES.items():
            if name in accepted_fps:
                continue
            with self.subTest(sample=name):
                found = detect_secrets_in_text(sample)
                if found:
                    flagged.append((name, [f["type"] for f in found]))
        self.assertEqual(flagged, [], f"FALSE POSITIVES: {flagged}")

    def test_short_ghp_mention_does_not_match(self):
        """The 36-char minimum must reject prose token mentions."""
        found = detect_secrets_in_text(NEGATIVES["prose_github"])
        self.assertFalse(any(f["type"] == "github_token" for f in found))


class TestSecretRedaction(unittest.TestCase):
    """Detection integrates with redaction utilities without crashing."""

    def test_scan_large_text_performance(self):
        big = (POSITIVES["aws_access_key"] + "\n" + NEGATIVES["prose_asia"] + "\n") * 2000
        import time
        t0 = time.monotonic()
        found = detect_secrets_in_text(big)
        dt = time.monotonic() - t0
        self.assertLess(dt, 5.0, f"scanning 6k lines took {dt:.1f}s")
        self.assertEqual(len(found), 2000)


if __name__ == "__main__":
    unittest.main()
