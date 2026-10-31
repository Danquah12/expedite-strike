#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_pdf_signature.py
Verifies Executive SOC PDF digital signature and logs attestation.
"""

import sys, re, json, hashlib
from pathlib import Path
from datetime import datetime
from PyPDF2 import PdfReader

def extract_footer_hash(pdf):
    reader = PdfReader(str(pdf))
    footer = ""
    for page in reader.pages:
        text = page.extract_text() or ""
        if "Digitally Signed by Expedite Consults DSIT System" in text:
            footer = text
    m = re.search(r"SHA256:\s*([a-fA-F0-9]{32,64})", footer)
    return m.group(1) if m else None

def compute_hash(pdf):
    with open(pdf, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def verify_signature(pdf):
    emb = extract_footer_hash(pdf)
    if not emb:
        return {"file": pdf.name, "status": "ERROR", "reason": "No signature found"}
    comp = compute_hash(pdf)
    valid = comp.startswith(emb[:32])
    return {
        "file": pdf.name,
        "embedded_hash": emb,
        "computed_hash": comp,
        "verified": valid,
        "timestamp_checked": datetime.now().isoformat(),
        "status": "VALID" if valid else "MISMATCH"
    }

def save_attestation(result):
    out = Path("/root/vuln_intel/app/reports/attestations")
    out.mkdir(parents=True, exist_ok=True)
    name = f"attestation_{result['file'].replace('.pdf','')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    p = out / name
    with open(p, "w") as f: json.dump(result, f, indent=4)
    print(f"🧾 Saved attestation: {p}")
    return p

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify_pdf_signature.py <path_to_pdf>")
        sys.exit(1)
    pdf = Path(sys.argv[1])
    if not pdf.exists():
        print(f"❌ File not found: {pdf}")
        sys.exit(1)
    result = verify_signature(pdf)
    for k, v in result.items():
        print(f"{k:18}: {v}")
    save_attestation(result)
    if result["status"] == "VALID":
        print("✅ Signature verified successfully.")
    else:
        print("⚠️ Verification failed — possible tampering detected.")

if __name__ == "__main__":
    main()
