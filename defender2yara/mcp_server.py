"""Model Context Protocol server exposing the threat REST API operations."""

from mcp.server.fastmcp import FastMCP
from peewee import DoesNotExist

from defender2yara.defender.dbthreat import db
from defender2yara.threat_api import get_threat_details
from defender2yara.threat_api import search_threats as search_threat_records

mcp = FastMCP("defender2db")


@mcp.tool()
def search_threats(threat_name: str) -> list[dict[str, object]]:
    """Search threats by a case-sensitive name substring (REST: GET /api/threats)."""
    query = threat_name.strip()
    if not query:
        raise ValueError("Query parameter 'threat_name' is required.")
    return search_threat_records(query)


@mcp.tool()
def get_threat(name: str) -> dict[str, object]:
    """Get full details for an exact threat name (REST: GET /api/threat)."""
    threat_name = name.strip()
    if not threat_name:
        raise ValueError("Query parameter 'name' is required.")
    try:
        return get_threat_details(threat_name)
    except DoesNotExist as error:
        raise ValueError("Threat not found.") from error


def main() -> None:
    db.connect(reuse_if_open=True)
    try:
        mcp.run(transport="stdio")
    finally:
        if not db.is_closed():
            db.close()


if __name__ == "__main__":
    main()
