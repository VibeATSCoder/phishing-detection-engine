from __future__ import annotations

from typing import Any, Awaitable, Callable

from starlette.responses import JSONResponse


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Reject oversized declared and streamed HTTP request bodies."""

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = int(max_bytes)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        content_length = next(
            (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                declared = self.max_bytes + 1
            if declared < 0 or declared > self.max_bytes:
                await JSONResponse(status_code=413, content={"detail": "request body too large"})(
                    scope, receive, send
                )
                return

        observed = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal observed
            message = await receive()
            if message.get("type") == "http.request":
                observed += len(message.get("body", b""))
                if observed > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await JSONResponse(status_code=413, content={"detail": "request body too large"})(
                scope, receive, send
            )
