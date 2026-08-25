# Fixture: Flask app. The unguarded user-data route MUST fire; the
# @login_required variant MUST NOT. Routes are spaced with realistic handler
# bodies because the guard heuristic searches a ~400-char window around each
# decorator — real controllers have this much code between endpoints anyway.
from flask import Flask, Blueprint, jsonify, request

api = Blueprint("api", __name__, url_prefix="/api")

app = Flask(__name__)


@api.route("/health")
def health():
    return jsonify({"ok": True})


@api.route("/version")
def version():
    return jsonify({"version": "1.4.2"})


@api.route("/features")
def features():
    return jsonify({
        "flags": {
            "new_checkout": False,
            "beta_ui": True,
            "onboarding_v3": "canary",
            "legacy_import": False,
        }
    })


@api.route("/user/export")
def export_data():
    # Handles GDPR-style export requests for the requested account owner.
    # Builds a JSON document containing every profile field we store, plus
    # audit metadata about when each field was last updated, then streams it
    # back as an attachment. Large accounts page through results in chunks.
    account_id = request.args.get("id", type=int)
    if not account_id:
        return jsonify({"error": "id required"}), 400
    rows = db_fetch_all(
        "SELECT id, email, display_name, created_at, last_login_at "
        "FROM users WHERE id = %s ORDER BY created_at DESC",
        (account_id,),
    )
    events = db_fetch_all(
        "SELECT kind, occurred_at FROM audit_events WHERE user_id = %s",
        (account_id,),
    )
    return jsonify({"profile": rows, "events": events})


def db_fetch_all(query, params):
    raise NotImplementedError


@api.route("/user/settings")
@login_required
def settings():
    payload = request.get_json(silent=True) or {}
    return jsonify(payload)


def login_required(fn):
    return fn
