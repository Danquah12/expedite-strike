/**
 * Floating Progress Strip — injects a fixed bar at the body level (BOTTOM docked).
 * Monitors the hidden ext-floating-progress div for data updates.
 */
(function() {
    "use strict";

    var STRIP_ID = "aegis-floating-strip";
    var POLL_MS  = 600;

    function ensureStrip() {
        var el = document.getElementById(STRIP_ID);
        if (el) return el;
        el = document.createElement("div");
        el.id = STRIP_ID;
        /* BOTTOM docked — never covers the header */
        el.style.cssText =
            "position:fixed;bottom:0;top:auto;left:0;right:0;z-index:99999;" +
            "display:none;align-items:center;gap:14px;" +
            "background:linear-gradient(90deg,#060c12 0%,#08101a 50%,#060c12 100%);" +
            "border-top:2px solid rgba(0,200,140,0.4);" +
            "border-bottom:none;" +
            "padding:8px 24px;font-family:'JetBrains Mono',monospace;" +
            "box-shadow:0 -4px 24px rgba(0,200,140,0.18);" +
            "backdrop-filter:blur(12px);";
        el.innerHTML =
            '<span style="font-size:13px;margin-right:6px">📡</span>' +
            '<span id="afp-phase" style="color:#00c88c;font-size:11px;font-weight:900;letter-spacing:1px;margin-right:16px">IDLE</span>' +
            '<span style="color:#3a5060;font-size:8px;font-weight:700;letter-spacing:1.5px;margin-right:4px">TOOL</span>' +
            '<span id="afp-tool" style="color:#00e5ff;font-size:11px;font-weight:900;margin-right:12px">—</span>' +
            '<span id="afp-pct" style="color:#ffd700;font-size:11px;font-weight:900;margin-right:16px">0%</span>' +
            '<span style="flex:1"></span>' +
            '<div style="width:220px;height:5px;background:#1a2030;border-radius:3px;overflow:hidden">' +
                '<div id="afp-bar" style="width:0%;height:100%;border-radius:3px;' +
                    'background:linear-gradient(90deg,#00c88c,#00e5ff);transition:width 0.5s ease"></div>' +
            '</div>';
        document.body.appendChild(el);
        console.log('[Aegis] Floating strip v6 — bottom docked');
        return el;
    }

    function sync() {
        var src = document.getElementById("ext-floating-progress");
        if (!src) return;
        var strip = ensureStrip();

        // Read source Dash div style — if display is flex, show the strip
        var srcStyle = src.style.display || "none";
        if (srcStyle === "flex" || srcStyle === "block") {
            strip.style.display = "flex";
        } else {
            strip.style.display = "none";
            return;
        }

        // Copy phase
        var phSrc = document.getElementById("ext-fp-phase");
        var phDst = document.getElementById("afp-phase");
        if (phSrc && phDst) phDst.textContent = phSrc.textContent || "IDLE";

        // Copy tool
        var tlSrc = document.getElementById("ext-fp-tool");
        var tlDst = document.getElementById("afp-tool");
        if (tlSrc && tlDst) tlDst.textContent = tlSrc.textContent || "—";

        // Copy pct
        var pcSrc = document.getElementById("ext-fp-pct");
        var pcDst = document.getElementById("afp-pct");
        if (pcSrc && pcDst) pcDst.textContent = pcSrc.textContent || "0%";

        // Copy bar width
        var barSrc = document.getElementById("ext-fp-bar-fill");
        var barDst = document.getElementById("afp-bar");
        if (barSrc && barDst) barDst.style.width = barSrc.style.width || "0%";
    }

    // Poll continuously
    setInterval(sync, POLL_MS);
})();
