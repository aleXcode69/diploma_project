import json
import logging
from typing import Callable, Set, Tuple, Union

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.payload_crypto import decrypt_bytes, encrypt_bytes
from app.session_repository import SessionRepository

logger = logging.getLogger("crypto.middleware")

PUBLIC_EXACT: Set[str] = {"/", "/api/handshake", "/api/dashboard/state"}
PUBLIC_PREFIXES = ("/ws/", "/docs", "/redoc", "/openapi.json")

SessionContext = Tuple[str, bytes]
SessionResult = Union[SessionContext, JSONResponse]


class CryptoMiddleware(BaseHTTPMiddleware):
    """
    Промежуточный слой сквозной обработки защищённых запросов API.
    Выполняет верификацию сессии, дешифрацию входящего тела и шифрование JSON-ответов.
    """

    def __init__(self, app: ASGIApp, session_repository: SessionRepository) -> None:
        super().__init__(app)
        self.repository = session_repository

    @staticmethod
    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _is_public_route(self, path: str) -> bool:
        if path in PUBLIC_EXACT:
            return True
        return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)

    def _requires_crypto(self, path: str) -> bool:
        return path.startswith("/api/protected")

    async def _resolve_session(self, request: Request, path: str) -> SessionResult:
        ip = self._client_ip(request)
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            await self.repository.log_security_event("missing_session_header", None, ip)
            return JSONResponse(status_code=401, content={"detail": "Требуется заголовок X-Session-ID"})

        try:
            session_key = await self.repository.get_session_key(session_id)
        except KeyError:
            await self.repository.log_security_event("invalid_session", session_id, ip)
            return JSONResponse(status_code=401, content={"detail": "Сессия не найдена или истекла"})

        if path.startswith("/api/protected/") and not path.startswith("/api/protected/submit"):
            path_id = path.removeprefix("/api/protected/").split("/")[0]
            if path_id and path_id != session_id:
                await self.repository.log_security_event("session_id_mismatch", session_id, ip)
                return JSONResponse(
                    status_code=401,
                    content={"detail": "X-Session-ID не совпадает с идентификатором маршрута"},
                )

        logger.info("Middleware: сессия %s подтверждена для %s %s", session_id, request.method, path)
        return session_id, session_key

    async def _prepare_request_body(
        self, request: Request, session_key: bytes, session_id: str
    ) -> Union[Request, JSONResponse]:
        if request.method not in {"POST", "PUT", "PATCH"}:
            return request

        raw_body = await request.body()
        if not raw_body:
            return request

        try:
            decrypted = decrypt_bytes(session_key, raw_body)
            request.state.decrypted_data = json.loads(decrypted.decode("utf-8"))
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.error("Middleware: ошибка дешифрации: %s", exc)
            await self.repository.log_security_event("decryption_failed", session_id, self._client_ip(request))
            return JSONResponse(status_code=401, content={"detail": "Ошибка дешифрации полезной нагрузки"})

        async def receive() -> dict:
            return {"type": "http.request", "body": decrypted, "more_body": False}

        return Request(request.scope, receive)

    async def _encrypt_response_if_json(
        self, response: Response, session_key: bytes, session_id: str
    ) -> Response:
        if "application/json" not in response.headers.get("content-type", ""):
            return response

        body = b"".join([chunk async for chunk in response.body_iterator])
        if not body:
            return response

        try:
            encrypted_body = encrypt_bytes(session_key, body)
        except Exception as exc:
            logger.error("Middleware: ошибка шифрования ответа: %s", exc)
            return JSONResponse(status_code=500, content={"detail": "Ошибка шифрования ответа"})

        return Response(
            content=encrypted_body,
            status_code=response.status_code,
            media_type="application/json",
            headers={"X-Encrypted": "aes-256-gcm", "X-Session-ID": session_id},
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if self._is_public_route(path) or not self._requires_crypto(path):
            return await call_next(request)

        session = await self._resolve_session(request, path)
        if isinstance(session, JSONResponse):
            return session

        session_id, session_key = session
        request.state.session_id = session_id
        request.state.session_key = session_key

        prepared = await self._prepare_request_body(request, session_key, session_id)
        if isinstance(prepared, JSONResponse):
            return prepared
        request = prepared

        response = await call_next(request)
        return await self._encrypt_response_if_json(response, session_key, session_id)
