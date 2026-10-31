// Force-clear ALL Dash persistence and session data on every page load
// This ensures the dropdown always gets fresh values from the server
(function() {
    try {
        // Clear ALL sessionStorage (kills stale Dash component state)
        sessionStorage.clear();
        
        // Clear any localStorage Dash entries
        var toRemove = [];
        for (var i = 0; i < localStorage.length; i++) {
            var key = localStorage.key(i);
            if (key && (key.indexOf('_dash') !== -1 || key.indexOf('ext-') !== -1)) {
                toRemove.push(key);
            }
        }
        toRemove.forEach(function(k) { localStorage.removeItem(k); });
        
        console.log('[Aegis] Session/localStorage cleared — fresh component state');
    } catch(e) {
        console.warn('[Aegis] Cache clear error:', e);
    }
})();
