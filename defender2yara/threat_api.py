"""Shared threat API operations used by the REST and MCP servers."""

import pickle

from peewee import DoesNotExist

from defender2yara.defender.dbthreat import DbThreat


def threat_summary(db_threat: DbThreat) -> dict[str, object]:
    return {
        "name": db_threat.name,
        "sigs": db_threat.sigs,
        "sigcount": db_threat.sigcount,
    }


def search_threats(threat_name: str) -> list[dict[str, object]]:
    db_threats = DbThreat.select().where(DbThreat.name.contains(threat_name))
    return [threat_summary(threat) for threat in db_threats]


def threat_details(db_threat: DbThreat) -> dict[str, object]:
    threat = pickle.loads(db_threat.threatObject)
    details = threat_summary(db_threat)
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
            script.decode("utf-8", errors="replace") if isinstance(script, bytes) else script
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


def get_threat_details(threat_name: str) -> dict[str, object]:
    db_threat = DbThreat.get(DbThreat.name == threat_name)
    return threat_details(db_threat)
