from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from collections import Counter
from typing import List, Tuple
from defender2yara.defender.dbthreat import db, DbThreat, DbMetadata
from defender2yara.threat_api import get_threat_details, search_threats
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
        + threat.static_signatures
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


@views.route("/api/threats")
def api_search_threats():
    threat_name = request.args.get('threat_name', '').strip()
    if not threat_name:
        return jsonify({"error": "Query parameter 'threat_name' is required."}), 400

    return jsonify(search_threats(threat_name))


@views.route("/api/threat")
def api_get_threat():
    threat_name = request.args.get('name', '').strip()
    if not threat_name:
        return jsonify({"error": "Query parameter 'name' is required."}), 400

    try:
        return jsonify(get_threat_details(threat_name))
    except DoesNotExist:
        return jsonify({"error": "Threat not found."}), 404


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

