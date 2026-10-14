class ExtRejection(Exception):
    """A request rejected by an extension check; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
