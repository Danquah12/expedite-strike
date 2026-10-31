from core.context import AssessmentContext
from core.engine import FrameworkEngine

from modules.preengagement.scope import ScopeModule
from modules.ingestion.scan_loader import ScanIngestionModule
from modules.vuln_analysis.exploit_intel import ExploitIntelModule
from modules.vuln_analysis.risk_scoring import RiskScoringModule
from modules.vuln_analysis.metasploit_check import MetasploitCheckModule
from modules.vuln_analysis.metasploit_search import MetasploitSearchModule
from modules.attack_modeling.attack_chains import AttackChainBuilder
from modules.attack_modeling.attack_graph import AttackGraphBuilder
from modules.attack_modeling.graph_export import AttackGraphExporter


def main():
    context = AssessmentContext()
    engine = FrameworkEngine(context)

    # 1️⃣ Scope
    engine.register_module(
        ScopeModule(
            target="LAB_HOST",
            authorized=True
        )
    )

    # 2️⃣ Scan ingestion
    engine.register_module(
        ScanIngestionModule(
            nmap_dir="/mnt/scans/incoming/nmap",
            zap_dir="/mnt/scans/incoming/zap"
        )
    )

    # 3️⃣ Analysis pipeline (ORDER MATTERS)
    engine.register_module(ExploitIntelModule())
    engine.register_module(RiskScoringModule())
    engine.register_module(AttackChainBuilder())

    # 🔍 Metasploit correlation (SEARCH-ONLY, NO exploitation)
    engine.register_module(MetasploitSearchModule())

    # 🔐 Optional validation (CHECK-only)
    engine.register_module(MetasploitCheckModule())

    engine.register_module(AttackGraphBuilder())
    engine.register_module(
        AttackGraphExporter(output_dir="outputs")
    )

    engine.run()

    # === HOST-CENTRIC CONTEXT STATE ===
    print("\n=== HOST-CENTRIC CONTEXT STATE ===")
    print("Scope:", context.scope)

    for host, data in context.hosts.items():
        print(f"\nHost: {host}")
        print("  Ports:", data["ports"])
        print("  Services:", data["services"])

        if data.get("web_findings"):
            print("  Web Findings:", len(data["web_findings"]))

    print("\n=== EXPLOITS (HOST-AWARE) ===")
    print(context.exploits)

    print("\n=== RISK RESULTS ===")
    for r in context.risk_results:
        print(r)

    print("\n=== ATTACK CHAINS ===")
    for chain in context.attack_chains:
        print(chain)

    # 🔍 NEW: Metasploit search-only results
    print("\n=== METASPLOIT CANDIDATE MODULES (SEARCH-ONLY) ===")
    for host, mods in getattr(context, "msf_candidates", {}).items():
        print(f"\nHost: {host}")
        for m in mods:
            print(m)

    print("\n=== ATTACK GRAPH ===")
    print("Nodes:")
    for n in context.attack_graph["nodes"]:
        print(" ", n)

    print("\nEdges:")
    for src, dst in context.attack_graph["edges"]:
        print(f"  {src} -> {dst}")


def run_framework():
    main()


if __name__ == "__main__":
    main()

