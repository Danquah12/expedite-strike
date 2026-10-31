// ============================================================
// Browser Notification + Sound Alerts for System Health
// ============================================================

// Request permission for browser notifications
if (Notification.permission !== "granted") {
    Notification.requestPermission().then(function (permission) {
        console.log("Notification permission:", permission);
    });
}

// Listen for Dash updates (through hidden dcc.Store or DOM mutation)
const observer = new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
        if (mutation.target && mutation.target.innerText) {
            const text = mutation.target.innerText;

            // Match alert keywords
            if (text.includes("CRITICAL ALERT") || text.match(/CPU:\d{2,}/)) {
                console.log("⚠️ Critical alert detected in log.");

                // Play sound if available
                const audio = document.querySelector("#alert-sound");
                if (audio) {
                    audio.play().catch(() => {
                        console.warn("Audio autoplay blocked. User interaction required.");
                    });
                }

                // Show browser notification
                if (Notification.permission === "granted") {
                    new Notification("⚠️ Critical System Alert", {
                        body: text.slice(0, 120) + "...",
                        icon: "/assets/towson_logo.png"
                    });
                }
            }
        }
    });
});

// Observe the status log output div for updates
window.addEventListener("load", () => {
    const target = document.querySelector("#status-log-output");
    if (target) {
        observer.observe(target, { childList: true, subtree: true, characterData: true });
        console.log("🔍 Monitoring system health for alerts...");
    }
});
