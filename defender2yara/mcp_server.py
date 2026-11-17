"""Model Context Protocol server exposing the threat REST API operations."""

from mcp.server.fastmcp import FastMCP
from defender2yara.threat_api import get_signature_details, get_raw_record, RawUnavailableError
from defender2yara.threat_api import get_threat_details
from defender2yara.threat_api import search_threats as search_threat_records

mcp = FastMCP("defender2db")


@mcp.tool()
def search_threats(threat_name: str) -> list[dict[str, object]]:
    """Search threats by name substring (REST: GET /api/threats)."""
    query = threat_name.strip()
    if not query:
        raise ValueError("Query parameter 'threat_name' is required.")
    return search_threat_records(query)


@mcp.tool()
def get_threat(threat_id: int) -> dict[str, object]:
    """Get a threat by the local database ID returned by search_threats."""
    try:
        return get_threat_details(threat_id)
    except LookupError as error:
        raise ValueError(str(error)) from error


@mcp.tool()
def get_signature(signature_id: int) -> dict:
    """Read decoded JSON and provenance for a signature or framing record."""
    try:
        return get_signature_details(signature_id)
    except LookupError as error:
        raise ValueError(str(error)) from error


@mcp.tool()
def get_raw_signature(signature_id: int) -> dict:
    """Explicitly retrieve an exact TLV record, if raw capture was enabled."""
    try:
        return {'signature_id': signature_id, 'data_hex': get_raw_record(signature_id).hex()}
    except (LookupError, RawUnavailableError) as error:
        raise ValueError(str(error)) from error


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
