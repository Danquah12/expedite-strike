/*
 * anchor_tts.js
 * =============
 * Pure browser TTS for the AI News Anchor.
 * Directly attaches to:
 *   #anchor-speak-btn   — start speaking
 *   #anchor-stop-btn    — stop speaking
 *   #anchor-voice-select — voice preference
 *   #anchor-script-display — source text
 *   #anchor-tts-status  — status message
 *   #anchor-avatar-img  — visual animation
 *
 * Dash auto-loads all JS in /assets/ on every page.
 * We use a MutationObserver so the buttons work even
 * after lazy tab rendering.
 */

(function () {
    "use strict";

    var _speakBtn, _stopBtn, _statusEl, _scriptEl, _voiceEl, _avatarEl;
    var _animTimer = null;

    function findEls() {
        _speakBtn = document.getElementById("anchor-speak-btn");
        _stopBtn = document.getElementById("anchor-stop-btn");
        _statusEl = document.getElementById("anchor-tts-status");
        _scriptEl = document.getElementById("anchor-script-display");
        _voiceEl = document.getElementById("anchor-voice-select");
        _avatarEl = document.getElementById("anchor-avatar-img");
    }

    function setStatus(msg) {
        if (_statusEl) _statusEl.innerText = msg;
    }

    function getScript() {
        if (!_scriptEl) return "";
        var txt = _scriptEl.innerText || _scriptEl.textContent || "";
        if (txt.startsWith("Click") || txt.startsWith("🔄")) return "";
        return txt.trim();
    }

    function stoplAll() {
        window.speechSynthesis && window.speechSynthesis.cancel();
        clearInterval(_animTimer);
        if (_avatarEl) {
            _avatarEl.style.animation = "";
            _avatarEl.style.filter = "";
        }
        setStatus("⏹ Stopped");
    }

    function pickVoice(pref) {
        var voices = window.speechSynthesis.getVoices();
        var picked = null;
        pref = pref || "en-US-female";
        for (var i = 0; i < voices.length; i++) {
            var v = voices[i];
            if (pref === "en-US-female" && v.lang === "en-US" &&
                /female|zira|aria|jenny|samantha|susan/i.test(v.name)) {
                picked = v; break;
            }
            if (pref === "en-US-male" && v.lang === "en-US" &&
                /male|david|mark|guy|eric/i.test(v.name)) {
                picked = v; break;
            }
            if (pref === "en-GB-male" && v.lang === "en-GB") {
                picked = v; break;
            }
        }
        if (!picked) {
            for (var j = 0; j < voices.length; j++) {
                if (voices[j].lang.startsWith("en")) { picked = voices[j]; break; }
            }
        }
        return picked;
    }

    function speak() {
        // Server-side TTS handles audio generation via Dash callback.
        // Browser speechSynthesis is disabled to prevent double audio.
        // The Dash callback on anchor-speak-btn produces the audio player.
        return;

        var utter = new SpeechSynthesisUtterance(script);
        utter.rate = 0.88;
        utter.pitch = 1.0;

        var pref = _voiceEl ? (_voiceEl.value || "en-US-female") : "en-US-female";
        var voice = pickVoice(pref);
        if (voice) utter.voice = voice;

        var secs = Math.ceil(script.length / 14);
        setStatus("🔊 Broadcasting live — ~" + secs + "s");

        // Avatar bob animation while speaking
        utter.onstart = function () {
            if (_avatarEl) {
                _avatarEl.style.animation = "avatarBob 0.25s ease-in-out infinite alternate";
                _avatarEl.style.filter = "drop-shadow(0 0 10px #ffcc00) brightness(1.1)";
            }
        };
        utter.onend = function () {
            if (_avatarEl) {
                _avatarEl.style.animation = "";
                _avatarEl.style.filter = "";
            }
            setStatus("✅ Broadcast complete");
        };
        utter.onerror = function (e) {
            if (_avatarEl) {
                _avatarEl.style.animation = "";
                _avatarEl.style.filter = "";
            }
            setStatus("⚠️ TTS error: " + e.error);
        };

        if (window.speechSynthesis.getVoices().length > 0) {
            window.speechSynthesis.speak(utter);
        } else {
            window.speechSynthesis.onvoiceschanged = function () {
                var v2 = pickVoice(pref);
                if (v2) utter.voice = v2;
                window.speechSynthesis.speak(utter);
            };
        }
    }

    function attach() {
        findEls();
        if (!_speakBtn || _speakBtn._ttsAttached) return;

        // NOTE: Speak button is handled by Dash server-side callback (OpenAI/espeak TTS).
        // Do NOT attach a JS click handler here — it blocks Dash's event propagation.

        _stopBtn && _stopBtn.addEventListener("click", function () {
            stoplAll();
        });

        _speakBtn._ttsAttached = true;
    }

    // Attach on load and re-attach after Dash re-renders (lazy tabs)
    document.addEventListener("DOMContentLoaded", attach);

    // MutationObserver: re-run attach whenever Dash renders new components
    var observer = new MutationObserver(function () { attach(); });
    observer.observe(document.body || document.documentElement, {
        childList: true,
        subtree: true,
    });

})();
