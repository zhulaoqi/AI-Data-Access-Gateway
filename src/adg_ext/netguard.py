"""Source-address restriction for the extension surfaces."""

import ipaddress

from fastapi import HTTPException, Request, status


def check_source(request: Request, cidrs: str) -> None:
    """Reject callers outside ``cidrs`` (comma separated). An empty setting allows everyone."""

    entries = [c.strip() for c in cidrs.split(",") if c.strip()]
    if not entries:
        return
    host = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        for entry in entries:
            try:
                if address in ipaddress.ip_network(entry, strict=False):
                    return
            except ValueError:
                continue
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Source not allowed")
