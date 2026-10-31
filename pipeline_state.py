"""
Pipeline Stage Status — Shared state for the autonomous pentest pipeline.

Both pentest_console.py and ui_pentest.py import this module to read/write
per-stage completion flags, avoiding circular imports.
"""

# Per-stage completion tracking.
# Values: "idle" | "running" | "complete"
PIPELINE_STAGE_STATUS = {
    "assessment":   "idle",
    "enumeration":  "idle",
    "exploitation": "idle",
    "postex":       "idle",
    "reporting":    "idle",
}


def reset_all():
    """Reset every stage back to idle — called when starting a new pipeline run."""
    for key in PIPELINE_STAGE_STATUS:
        PIPELINE_STAGE_STATUS[key] = "idle"
