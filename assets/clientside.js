if (!window.clientside) window.clientside = {};

window.clientside.showContextMenu = function (data) {
    if (!data) {
        return window.dash_clientside.no_update;
    }

    const menu = document.getElementById("context-menu");
    if (menu) {
        menu.style.left = "200px";
        menu.style.top = "200px";
        menu.style.display = "block";
    }

    return data.id;
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Hub — document-level event delegation for dynamically-rendered buttons
// Fires for ANY click matching "plugin-open-*" regardless of when added to DOM.
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
    document.body.addEventListener("click", function (e) {
        const btn = e.target.closest("button[id^='plugin-open-']");
        if (!btn) return;

        const pid = btn.getAttribute("id").replace("plugin-open-", "");
        if (!pid) return;

        // Hide the grid immediately for instant feedback
        const grid = document.getElementById("plugin-hub-grid");
        const detail = document.getElementById("plugin-detail-area");
        if (grid) grid.style.display = "none";
        if (detail) detail.innerHTML = "<div style='color:#aaa;padding:40px;text-align:center'>⏳ Loading " + pid + " plugin...</div>";

        // POST to Dash callback endpoint for show_plugin_detail(pid)
        const body = {
            output: "plugin-hub-grid.style...plugin-detail-area.children",
            outputs: [
                { "id": "plugin-hub-grid", "property": "style" },
                { "id": "plugin-detail-area", "property": "children" }
            ],
            inputs: [{ "id": "plugin-selected-store", "property": "data", "value": pid }],
            changedPropIds: ["plugin-selected-store.data"],
            state: []
        };

        fetch("/_dash-update-component", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                // Dash will update plugin-detail-area via its normal reconciler
                // If that doesn't happen, force-update the store so Dash reacts
                window._dashPrivateStore && window._dashPrivateStore.dispatch({
                    type: "ON_PROP_CHANGE",
                    id: "plugin-selected-store",
                    props: { data: pid }
                });
            })
            .catch(function () {
                if (detail) detail.innerHTML = "<div style='color:#f66;padding:20px'>Error loading plugin. Is the server running?</div>";
            });
    });
});

/* ═══ Dash Error Recovery v1 — DISABLED ═══
   Was causing potential loops with ext-pentest tab rendering.
   The floating strip handles progress display independently. */

