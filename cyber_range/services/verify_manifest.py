"""
EXPEDITE STRIKE V3.2 — Standalone Database-Free Cryptographic Evidence Bundle Verifier
======================================================================================
Proves that an external auditor, client, or CI/CD pipeline can independently verify:
  1. Every finding's canonical SHA-256 evidence digest (`{host}:{port}:{scanner}:{evidence}`),
  2. The deterministic SHA-256 Merkle Root over all finding provenance digests,
  3. The RFC 8032 Ed25519 asymmetric digital signature over the manifest using ONLY the
     exported public key (`ed25519_pub.pem` or hex), with zero access to XStrike's private
     signing key, symmetric HMAC key, or internal SQLite database (`v2_intelligence.db`),
  4. Before-and-after remediation evidence hashes and negative-control host-alive proofs,
  5. Active 1-byte tamper-detection self-test (proving any mutation invalidates the Ed25519 signature).

Usage (CLI):
  python -m cyber_range.services.verify_manifest \
      --bundle cyber_range/reports/XStrike_Evidence_Bundle.json \
      --pubkey cyber_range/reports/ed25519_pub.pem
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional


def _sha256_hex(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def verify_ed25519_pem_or_hex(payload: str, signature_hex: str, pubkey_pem: Optional[str] = None, pubkey_hex: Optional[str] = None) -> bool:
    """Verify an RFC 8032 Ed25519 signature using only the public key (PEM or 32-byte hex)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        sig_bytes = bytes.fromhex((signature_hex or "").strip())
        if pubkey_pem and "BEGIN PUBLIC KEY" in pubkey_pem:
            pub_key = serialization.load_pem_public_key(pubkey_pem.encode("utf-8"))
        elif pubkey_hex:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex.strip()))
        else:
            return False

        if not isinstance(pub_key, ed25519.Ed25519PublicKey):
            return False
        pub_key.verify(sig_bytes, (payload or "").encode("utf-8", errors="replace"))
        return True
    except Exception:
        return False


def verify_exported_bundle_standalone(
    bundle_data: Dict[str, Any],
    pubkey_pem: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Independently verify an exported XStrike V3.2 Evidence Bundle without touching SQLite
    or any internal XStrike secrets.
    """
    manifest = bundle_data.get("manifest") or {}
    records: List[Dict[str, Any]] = bundle_data.get("evidence_records") or []
    remediation_records: List[Dict[str, Any]] = bundle_data.get("remediation_verification_records") or []

    assessment_id = manifest.get("assessment_id", "")
    gen_ts = manifest.get("generated_at_utc", "")
    qgate_bound = manifest.get("quality_gate_bound", "20/20")
    expected_root = manifest.get("manifest_root_sha256", "")
    ed25519_sig = manifest.get("manifest_ed25519_signature", "")
    ed25519_pub_hex = manifest.get("ed25519_public_key_hex", "")
    pem_to_use = pubkey_pem or manifest.get("ed25519_public_key_pem", "")

    mismatches: List[str] = []
    record_sha256_verified = 0
    leaf_digests: List[str] = []

    for rec in records:
        fid = rec.get("finding_id", "")
        pid = rec.get("provenance_id", "")
        host = rec.get("host", "")
        port = rec.get("port", "")
        scanner = rec.get("scanner", "")
        raw_ev = rec.get("raw_evidence", "")
        claimed_sha = rec.get("evidence_sha256", "")

        canonical_payload = f"{host}:{port}:{scanner}:{raw_ev}"
        recomputed_sha = _sha256_hex(canonical_payload)
        if recomputed_sha == claimed_sha:
            record_sha256_verified += 1
        else:
            mismatches.append(f"{fid}: Record SHA-256 mismatch (expected {recomputed_sha[:16]}, got {claimed_sha[:16]})")
        leaf_digests.append(f"{fid}:{pid}:{recomputed_sha}")

    recomputed_merkle_root = _sha256_hex("\n".join(leaf_digests))
    merkle_root_verified = (recomputed_merkle_root == expected_root) and len(expected_root) == 64
    if not merkle_root_verified:
        mismatches.append(f"Merkle root mismatch: recomputed {recomputed_merkle_root[:16]} != manifest {expected_root[:16]}")

    manifest_payload = f"{assessment_id}|{gen_ts}|{len(records)}|{recomputed_merkle_root}|{qgate_bound}"
    ed25519_verified = verify_ed25519_pem_or_hex(
        manifest_payload,
        ed25519_sig,
        pubkey_pem=pem_to_use,
        pubkey_hex=ed25519_pub_hex,
    )
    if not ed25519_verified:
        mismatches.append("Ed25519 asymmetric public-key signature verification failed")

    # 1-byte tamper self-test using ONLY the public key
    tampered_payload = (
        f"{assessment_id}|{gen_ts}|{len(records)}|"
        f"{recomputed_merkle_root[:-1]}{'0' if recomputed_merkle_root[-1:] != '0' else '1'}|{qgate_bound}"
    )
    tamper_rejected = not verify_ed25519_pem_or_hex(
        tampered_payload,
        ed25519_sig,
        pubkey_pem=pem_to_use,
        pubkey_hex=ed25519_pub_hex,
    )
    if not tamper_rejected:
        mismatches.append("Ed25519 tamper self-test failed to reject 1-byte mutation")

    # Verify Remediation Before/After & Negative-Control Evidence Hashes
    rem_verified_count = 0
    for rrec in remediation_records:
        rfid = rrec.get("finding_id", "")
        b_ev = rrec.get("before_evidence", "")
        a_ev = rrec.get("after_evidence", "")
        nc_ev = rrec.get("negative_control_evidence", "")
        b_ok = (_sha256_hex(b_ev) == rrec.get("before_sha256", ""))
        a_ok = (_sha256_hex(a_ev) == rrec.get("after_sha256", ""))
        nc_ok = (_sha256_hex(nc_ev) == rrec.get("negative_control_sha256", ""))
        if b_ok and a_ok and nc_ok:
            rem_verified_count += 1
        else:
            mismatches.append(f"Remediation record {rfid} hash mismatch (before={b_ok}, after={a_ok}, neg_ctrl={nc_ok})")

    overall_ok = (
        len(records) > 0
        and record_sha256_verified == len(records)
        and merkle_root_verified
        and ed25519_verified
        and tamper_rejected
        and rem_verified_count == len(remediation_records)
        and len(mismatches) == 0
    )

    return {
        "standalone_verified": overall_ok,
        "verification_mode": "STANDALONE_PUBLIC_KEY_AND_EXPORTED_BUNDLE_NO_DB",
        "database_dependency": "NONE (Verified 100% from exported JSON bundle + Ed25519 public key PEM)",
        "assessment_id": assessment_id,
        "total_exported_records": len(records),
        "record_sha256_verified_count": record_sha256_verified,
        "recomputed_merkle_root_sha256": recomputed_merkle_root,
        "merkle_root_matched": merkle_root_verified,
        "ed25519_public_key_verified": ed25519_verified,
        "ed25519_tamper_self_test": "PASSED (1-byte mutation rejected by Ed25519 public key)" if tamper_rejected else "FAILED",
        "remediation_records_verified": f"{rem_verified_count}/{len(remediation_records)}",
        "mismatches": mismatches,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone Database-Free Verifier for XStrike V3.2 Signed Evidence Bundles"
    )
    parser.add_argument(
        "--bundle",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "XStrike_Evidence_Bundle.json"),
        help="Path to exported XStrike_Evidence_Bundle.json",
    )
    parser.add_argument(
        "--pubkey",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "ed25519_pub.pem"),
        help="Path to exported Ed25519 public key PEM file",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.bundle):
        print(json.dumps({"standalone_verified": False, "error": f"Bundle file not found: {args.bundle}"}, indent=2))
        return 1

    with open(args.bundle, "r", encoding="utf-8") as fh:
        bundle_data = json.load(fh)

    pubkey_pem = None
    if args.pubkey and os.path.exists(args.pubkey):
        with open(args.pubkey, "r", encoding="utf-8") as pfh:
            pubkey_pem = pfh.read()

    res = verify_exported_bundle_standalone(bundle_data, pubkey_pem=pubkey_pem)
    print(json.dumps(res, indent=2))
    return 0 if res.get("standalone_verified") else 1


if __name__ == "__main__":
    sys.exit(main())
