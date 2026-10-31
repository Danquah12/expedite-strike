/* ==========================================================
   Voice Assistant — STT + TTS + Dash Integration
   ----------------------------------------------------------
   This script connects browser speech recognition (STT),
   sends recognized text into Dash, and plays back LLM
   responses using speech synthesis.
   ========================================================== */

window.addEventListener("DOMContentLoaded", function () {
  console.log("🎙️ Voice Assistant loaded...");

  // -------------------------------------------------------------------
  //  Grab UI elements from Dash layout
  // -------------------------------------------------------------------
  const startBtn = document.getElementById("voice-record-btn");
  const stopBtn = document.getElementById("voice-stop-btn");
  const statusDiv = document.getElementById("voice-status");
  const transcriptDiv = document.getElementById("voice-transcript");
  const responseDiv = document.getElementById("voice-response");

  // Hidden store that Dash listens to
  const voiceStore = document.getElementById("voice-input");

  if (!startBtn || !stopBtn || !voiceStore) {
    console.warn("Voice elements not found in DOM.");
    return;
  }

  // -------------------------------------------------------------------
  //  Speech Recognition Setup
  // -------------------------------------------------------------------
  const SpeechRecognition =
    window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    statusDiv.textContent = "🚫 Speech Recognition not supported in this browser.";
    return;
  }

  const recognition = new SpeechRecognition();
  recognition.lang = "en-US";
  recognition.continuous = true;
  recognition.interimResults = false;

  // -------------------------------------------------------------------
  //  Start Recording
  // -------------------------------------------------------------------
  startBtn.addEventListener("click", () => {
    recognition.start();
    statusDiv.textContent = "🎤 Listening...";
  });

  // -------------------------------------------------------------------
  //  Stop Recording
  // -------------------------------------------------------------------
  stopBtn.addEventListener("click", () => {
    recognition.stop();
    statusDiv.textContent = "🛑 Stopped.";
  });

  // -------------------------------------------------------------------
  //  When speech is recognized
  // -------------------------------------------------------------------
  recognition.addEventListener("result", (event) => {
    const text =
      event.results[event.results.length - 1][0].transcript.trim();

    transcriptDiv.textContent = text;
    statusDiv.textContent = "✅ Recognized: " + text;

    // ----------------------------------------------------------
    //  SEND recognized speech → Dash through dcc.Store
    // ----------------------------------------------------------
    console.log("Sending STT → Dash:", text);

    // Write recognized text into hidden store
    const payload = {
      event: "voice_input",
      text: text,
      timestamp: Date.now(),
    };


    voiceStore.dataset.store = JSON.stringify(payload);
    voiceStore.dispatchEvent(new Event("change", { bubbles: true }));

    voiceStore.dispatchEvent(new Event("change", { bubbles: true }));

    // ----------------------------------------------------------
    //  Basic TTS acknowledgment
    // ----------------------------------------------------------
    if ("speechSynthesis" in window) {
      const utter = new SpeechSynthesisUtterance(
        "You said: " + text + ". Processing now."
      );
      utter.rate = 1;
      window.speechSynthesis.speak(utter);
    }
  });

  recognition.addEventListener("error", (e) => {
    statusDiv.textContent = "⚠️ Error: " + e.error;
  });

  // -------------------------------------------------------------------
  //  Listen for Dash → voice.js events (AI response to speak aloud)
  // -------------------------------------------------------------------
  document.addEventListener("voice_ai_response", (evt) => {
    const msg = evt.detail.response;
    responseDiv.textContent = msg;

    // Speak the AI response
    if ("speechSynthesis" in window) {
      const utter = new SpeechSynthesisUtterance(msg);
      utter.rate = 1;
      utter.pitch = 1;
      utter.volume = 1;
      window.speechSynthesis.speak(utter);
    }
  });
});
