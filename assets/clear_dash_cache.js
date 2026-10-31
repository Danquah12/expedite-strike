/**
 * clear_dash_cache.js — clears stale Dash component state on page load.
 * Dash stores dropdown values in sessionStorage/localStorage. When we change
 * layout defaults, the old browser-cached values override the new ones.
 * This script wipes Dash-related storage keys on every page load.
 */
(function() {
    try {
        // Clear Dash-specific keys from sessionStorage
        var keys = Object.keys(sessionStorage);
        for (var i = 0; i < keys.length; i++) {
            if (keys[i].indexOf('dash') !== -1 || keys[i].indexOf('_dash') !== -1) {
                sessionStorage.removeItem(keys[i]);
            }
        }
        // Clear Dash-specific keys from localStorage
        keys = Object.keys(localStorage);
        for (var j = 0; j < keys.length; j++) {
            if (keys[j].indexOf('dash') !== -1 || keys[j].indexOf('_dash') !== -1 ||
                keys[j].indexOf('nmap-profile') !== -1 || keys[j].indexOf('scanner-select') !== -1) {
                localStorage.removeItem(keys[j]);
            }
        }
    } catch(e) {
        // Ignore storage access errors
    }
})();
