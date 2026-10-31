"""
app/nl_interface.py

Routes natural language queries to structured enrichment functions.
"""

import re
from integrations.orchestrator import enrich_cve

def api_nl_query(user_query: str):
    """
    Interpret a natural-language query and route it to the proper function.
    Example inputs:
      - "Tell me about CVE-2023-23397"
      - "Show recent CVEs"
      - "Get exploits for CVE-2022-26134"
    """
    q = user_query.strip().lower()

    # Handle specific CVE queries
    match = re.search(r"(cve-\d{4}-\d+)", q, re.I)
    if match:
        cve = match.group(1).upper()
        return enrich_cve(cve)

    # Example placeholder for "recent CVEs" or others
    if "recent" in q or "latest" in q:
        return {"message": "Recent CVE retrieval not yet implemented."}

    return {"error": f"Unrecognized query: '{user_query}'"}
@app.route("/api/query", methods=["POST"])
def api_nl_query():
    payload = request.get_json() or {}
    q = (payload.get("q") or "").strip()
    if not q:
        return jsonify({"error":"empty query"}), 400

    # load intent map
    with open('/root/vuln_intel/integrations/intent_map.json') as fh:
        intent_map = json.load(fh).get("intents", {})

    ql = q.lower()

    # try regex-driven intent matching
    for name, meta in intent_map.items():
        pat = meta.get("pattern")
        m = re.search(pat, ql)
        if m:
            # extract first CVE-like group if present
            g = None
            for gr in m.groups():
                if gr and re.match(r'cve[- ]?\d{4}-\d+', gr, flags=re.I):
                    g = re.sub(r'[- ]', '-', gr.upper())
                    break
            # dispatch to actions
            if meta["action"] == "enrich_cve" and g:
                # call orchestrator that returns only metadata (no exploit code)
                out = enrich_cve(g)
                # sanitize: strip raw exploit code paths (only provide metadata)
                if 'exploitdb' in out and out['exploitdb'] and 'results' in out['exploitdb']:
                    # ensure we only return title/path/date/platform - DO NOT include code content
                    out['exploitdb']['results'] = [
                        {k:v for k,v in r.items() if k in ('title','path','date','platform','type')} 
                        for r in out['exploitdb'].get('results', [])
                    ]
                return jsonify(out)
            if meta["action"] == "check_exploit" and g:
                sx = searchsploit_for_cve(g)
                # return metadata only
                return jsonify(sx)
            if meta["action"] == "hosts_for_cve" and g:
                db = get_db()
                rows = db.execute("""
                    SELECT DISTINCT host, port, source FROM cve_assets WHERE cve_id = ? LIMIT 500
                """, (g,)).fetchall()
                return jsonify([dict(r) for r in rows])

    # fallback to previous patterns (keep earlier behavior)
    return jsonify({"error":"Could not parse query. Examples: 'show cves for host 192.168.73.10', 'hosts affected by CVE-2023-23397'"}), 400
