"""
VULNADO Flask Application
AI-Powered Vulnerability Analysis Chatbot
"""

import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add src to path so VULNADO modules are importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

# ---------------------------------------------------------------------------
# Lazy-load the chatbot so the server starts even if Neo4j is offline
# ---------------------------------------------------------------------------
_chatbot = None

def get_chatbot():
    global _chatbot
    if _chatbot is None:
        try:
            from VULNADO.bot.vulnerability_chatbot import VulnerabilityBot
            _chatbot = VulnerabilityBot()
            logger.info("Chatbot initialised successfully")
        except Exception as e:
            logger.warning(f"Chatbot init failed: {e}")
    return _chatbot


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "No message provided"}), 400

    bot = get_chatbot()
    if bot:
        try:
            result = bot.chat(message)
            # Pass through full chatbot response (answer, intent, confidence, entities, suggested_followups)
            return jsonify({
                "answer":             result.get("answer", ""),
                "intent":             result.get("intent", "general_security"),
                "confidence":         result.get("confidence", 0.0),
                "entities":           result.get("entities", {}),
                "suggested_followups": result.get("suggested_followups", []),
                "timestamp":          result.get("timestamp", datetime.utcnow().isoformat()),
            })
        except Exception as e:
            logger.error(f"Chat error: {e}")
            # Fall through to demo response

    # Demo / fallback when chatbot or Neo4j is unavailable
    return jsonify({
        "answer": (
            f"**Query received:** {message}\n\n"
            "⚠️ The knowledge graph (Neo4j) is currently offline on this instance. "
            "The full AI chatbot requires Neo4j to be running.\n\n"
            "**What VULNADO can answer when fully connected:**\n"
            "- CVE details, CVSS scores, affected packages\n"
            "- MITRE ATT&CK technique mapping\n"
            "- GitHub Advisory (GHSA) data\n"
            "- Remediation recommendations\n"
            "- Risk prioritization across 180 days of data"
        ),
        "intent": "general_security",
        "confidence": 1.0,
        "entities": {},
        "suggested_followups": [
            "What are the top critical CVEs in the last 30 days?",
            "What MITRE techniques are used in privilege escalation?",
            "How do I remediate a remote code execution vulnerability?",
        ],
        "timestamp": datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Starting VULNADO on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
