"""Shared bounds for a single data query on JDBC and MCP.

Profile specs allow ``query_timeout_seconds`` up to 600. The socket that waits
for that query must outlive the policy timeout, so the executor can cancel
first and the driver does not report a network error while the database is
still working. Scans and connection tests keep the shorter configured timeouts.
"""

MAX_QUERY_TIMEOUT_SECONDS = 600
# The admission queue is a separate limit (1–300s) and is included in the
# client-visible wait, because JDBC holds one protocol round trip for both.
MAX_QUEUE_TIMEOUT_SECONDS = 300
QUERY_TIMEOUT_GRACE_SECONDS = 60
RUNTIME_SOCKET_TIMEOUT_SECONDS = MAX_QUERY_TIMEOUT_SECONDS + QUERY_TIMEOUT_GRACE_SECONDS
CLIENT_WAIT_TIMEOUT_SECONDS = (
    MAX_QUEUE_TIMEOUT_SECONDS + MAX_QUERY_TIMEOUT_SECONDS + QUERY_TIMEOUT_GRACE_SECONDS
)
