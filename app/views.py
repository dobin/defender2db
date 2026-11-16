from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from collections import Counter
from typing import List, Tuple
from defender2yara.defender.dbthreat import db, DbThreat, DbMetadata
from peewee import DoesNotExist
import urllib.parse
import pickle
from defender2yara.util.utils import hexdump_s

views = Blueprint('views', __name__)
logger = logging.getLogger("Views")


@views.route("/")
def index():
    metadata = None
    try:
        metadata = DbMetadata.get()
    except Exception as e:
        logger.warning(f"Could not retrieve metadata: {e}")

    return render_template('index.html', metadata=metadata)


@views.route("/threat")
def get_threat():
    threat_name = request.args.get('name', '').strip()
    if not threat_name:
        return redirect(url_for('views.index'))

    print("Showing threat:", threat_name, flush=True)
    dbThreat = DbThreat.get(DbThreat.name == threat_name)
    threat = pickle.loads(dbThreat.threatObject)

    decoded_signatures = (
        threat.dexhstr_signatures + threat.aggregator_signatures
        + threat.version_checks + threat.behavior_signatures
        + threat.nid_signatures + threat.pehstr_signatures
    )
    decoded_records = {(sig.sig_type, sig.sig_data) for sig in decoded_signatures}
    skip_signatures = {
        "SIGNATURE_TYPE_PEHSTR",
        "SIGNATURE_TYPE_THREAT_BEGIN",
        "SIGNATURE_TYPE_THREAT_END",
        "SIGNATURE_TYPE_LUASTANDALONE",
        "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    }

    sigs = []
    for sig in threat.signatures:
        if sig.sig_type in skip_signatures or (sig.sig_type, sig.sig_data) in decoded_records:
            continue

        s = ""
        s += "{} {} {}\n".format(sig.sig_type_id, sig.sig_type, sig.size)
        s += hexdump_s(sig.sig_data)
        sigs.append(s)

    signature_counts = Counter(sig.sig_type for sig in threat.signatures)
    return render_template(
        'threat.html',
        threat=threat,
        signatures=sigs,
        signature_counts=sorted(signature_counts.items()),
    )


@views.route("/search")
def search_threat():
    threat_name = request.args.get('threat_name', '').strip()
    if not threat_name:
        return redirect(url_for('views.index'))

    print("Searching for threat:", threat_name)
    dbThreats = DbThreat.select().where(DbThreat.name.contains(threat_name))
    print("Found", len(dbThreats), "threats in the database.", flush=True)

    return render_template('threats.html', threats=dbThreats, threat_name=threat_name)


def _threat_summary(db_threat):
    return {
        "name": db_threat.name,
        "sigs": db_threat.sigs,
        "sigcount": db_threat.sigcount,
    }


def _threat_details(db_threat):
    threat = pickle.loads(db_threat.threatObject)
    details = _threat_summary(db_threat)
    details.update({
        "id": getattr(threat, "id", None),
        "category": getattr(threat, "category", None),
        "severity": getattr(threat, "severity", None),
        "type": getattr(threat, "type", None),
        "platform": getattr(threat, "platform", None),
        "family": getattr(threat, "family", None),
        "variant": getattr(threat, "variant", None),
        "suffixes": getattr(threat, "suffixes", None),
        "yara_rules": getattr(threat, "yara_rules", []),
        "lua_scripts": [
            script.decode('utf-8', errors='replace') if isinstance(script, bytes) else script
            for script in getattr(threat, "lua_scripts", [])
        ],
        "revoked_certs": [],
        "signatures": [],
    })

    for sig in getattr(threat, "signatures", []):
        sig_data = getattr(sig, "sig_data", b"")
        if getattr(sig, "sig_type", None) == "SIGNATURE_TYPE_REVOKED_CERTIFICATE":
            details["revoked_certs"].append(sig_data[3:23].hex())
        details["signatures"].append({
            "type_id": getattr(sig, "sig_type_id", None),
            "type": getattr(sig, "sig_type", None),
            "size": getattr(sig, "size", None),
            "data_hex": sig_data.hex() if isinstance(sig_data, bytes) else str(sig_data),
        })

    return details


@views.route("/api/threats")
def api_search_threats():
    threat_name = request.args.get('threat_name', '').strip()
    if not threat_name:
        return jsonify({"error": "Query parameter 'threat_name' is required."}), 400

    db_threats = DbThreat.select().where(DbThreat.name.contains(threat_name))
    return jsonify([_threat_summary(threat) for threat in db_threats])


@views.route("/api/threat")
def api_get_threat():
    threat_name = request.args.get('name', '').strip()
    if not threat_name:
        return jsonify({"error": "Query parameter 'name' is required."}), 400

    try:
        db_threat = DbThreat.get(DbThreat.name == threat_name)
    except DoesNotExist:
        return jsonify({"error": "Threat not found."}), 404

    return jsonify(_threat_details(db_threat))


@views.app_template_filter('urlencode')
def urlencode_filter(s):
    if isinstance(s, str):
        return urllib.parse.quote_plus(s)
    return s

@views.app_template_filter('hexencode')
def hexencode_filter(s):
    if isinstance(s, str):
        return hexdump_s(s)
    return s

@views.app_template_filter('bytes_to_str')
def bytes_to_str(s: bytes) -> str:
    if isinstance(s, bytes):
        return s.decode('utf-8', errors='replace')
    return str(s)

