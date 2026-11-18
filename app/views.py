from collections import Counter
from io import BytesIO
import json
import os
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, send_file, url_for
from sqlalchemy import select

from defender2yara.defender.dbthreat import DEFAULT_DATABASE, ImportInfo, read_session
from defender2yara.threat_api import (
    RawUnavailableError, get_raw_record, get_signature_details, get_threat_details,
    search_threats,
)

views = Blueprint('views', __name__)

SIGNATURE_TEMPLATES = {
    'STATIC': 'signatures/static.html',
    'PEHSTR': 'signatures/pehstr.html',
    'PEHSTR_EXT': 'signatures/pehstr_ext.html',
    'DEXHSTR_EXT': 'signatures/dexhstr_ext.html',
    'CMDHSTR_EXT': 'signatures/cmdhstr_ext.html',
    'CMDHSTR_FAST_EXT': 'signatures/cmdhstr_ext.html',
    'AAGGREGATOR': 'signatures/aaggregator.html',
    'AAGGREGATOREX': 'signatures/aaggregatorex.html',
    'VERSIONCHECK': 'signatures/versioncheck.html',
    'SIGTREE': 'signatures/sigtree.html',
    'SIGTREE_EXT': 'signatures/sigtree_ext.html',
    'SIGTREE_BM': 'signatures/sigtree_bm.html',
    'NID': 'signatures/nid.html',
    'NID64': 'signatures/nid64.html',
    'SNID': 'signatures/snid.html',
    'REVOKED_CERTIFICATE': 'signatures/revoked_certificate.html',
    'NSCRIPT_SP': 'signatures/nscript_sp.html',
    'NSCRIPT_NORMAL': 'signatures/nscript_normal.html',
    'NSCRIPT_BRUTE': 'signatures/nscript_brute.html',
    'MACRO_SOURCE': 'signatures/macro_source.html',
    'MACRO_PCODE': 'signatures/macro_pcode.html',
    'MACRO_PCODE64': 'signatures/macro_pcode.html',
    'LUASTANDALONE': 'signatures/lua_standalone.html',
    'CKSIMPLEREC': 'signatures/ckrecord.html',
    'CKOLDREC': 'signatures/ckrecord.html',
    'FILEPATH': 'signatures/pathname.html',
    'FOLDERNAME': 'signatures/pathname.html',
}

SIGNATURE_DESCRIPTIONS_PATH = Path(__file__).parent / 'static' / 'sigs' / 'signatures.json'


def load_signature_descriptions():
    try:
        with SIGNATURE_DESCRIPTIONS_PATH.open(encoding='utf-8') as descriptions_file:
            return json.load(descriptions_file)
    except (OSError, json.JSONDecodeError):
        return {}


def database():
    return current_app.config.get('DATABASE', DEFAULT_DATABASE)


@views.route('/')
def index():
    with read_session(database()) as session:
        metadata = session.scalar(select(ImportInfo).where(ImportInfo.id == 1))
        domain = (os.environ.get('DOMAIN') or request.url_root.rstrip('/')).rstrip('/')
        return render_template(
            'index.html', metadata=metadata, domain=domain,
            mcp_endpoint=f'{domain}/mcp' if domain else '/mcp',
        )


@views.route('/about')
def about():
    return render_template('about.html')


@views.route('/threat/<int:local_id>')
def get_threat(local_id):
    try:
        threat = get_threat_details(local_id, database=database())
    except LookupError:
        abort(404)
    groups = {}
    for signature in threat['signatures']:
        kind = signature['type'].removeprefix('SIGNATURE_TYPE_')
        signature['template'] = SIGNATURE_TEMPLATES.get(kind, 'signatures/generic.html')
        groups.setdefault(kind, []).append(signature)
    return render_template(
        'threat.html', threat=threat, groups=groups,
        signature_counts=sorted(Counter(sig['type'] for sig in threat['signatures']).items()),
        signature_descriptions=load_signature_descriptions(),
    )


@views.route('/search')
def search_threat():
    query = request.args.get('threat_name', '').strip()
    if not query:
        return redirect(url_for('views.index'))
    return render_template('threats.html', threats=search_threats(query, database=database()), threat_name=query)


@views.route('/api/threats')
def api_search_threats():
    query = request.args.get('threat_name', '').strip()
    if not query:
        return jsonify({'error': "Query parameter 'threat_name' is required."}), 400
    return jsonify(search_threats(query, database=database()))


@views.route('/api/threats/<int:local_id>')
def api_get_threat(local_id):
    try:
        return jsonify(get_threat_details(local_id, database=database()))
    except LookupError:
        return jsonify({'error': 'Threat not found.'}), 404


@views.route('/api/signatures/<int:local_id>')
def api_get_signature(local_id):
    try:
        return jsonify(get_signature_details(local_id, database=database()))
    except LookupError:
        return jsonify({'error': 'Signature not found.'}), 404


@views.route('/api/signatures/<int:local_id>/raw')
def api_get_raw_record(local_id):
    try:
        raw = get_raw_record(local_id, database=database())
    except RawUnavailableError:
        return jsonify({'error': 'Raw record unavailable; rebuild with --convert --include-raw.'}), 409
    except LookupError:
        return jsonify({'error': 'Signature not found.'}), 404
    return send_file(BytesIO(raw), mimetype='application/octet-stream', as_attachment=True,
                     download_name=f'signature-{local_id}.tlv')


@views.app_template_filter('hexnum')
def hexnum(value, width=0):
    return f'0x{value:0{width}x}' if isinstance(value, int) else str(value or '')


@views.app_template_filter('hexalgo')
def hexalgo(value):
    return f'0x{int(value) & 0x7000:04x}' if isinstance(value, int) else ''


@views.app_template_filter('hextext')
def hextext(value):
    try:
        return bytes.fromhex(value).decode('utf-8', errors='replace')
    except (TypeError, ValueError):
        return ''

