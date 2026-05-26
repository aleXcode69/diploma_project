import asyncio
import datetime as dt
import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from app.crypto import HybridCryptoService
from app.middleware import CryptoMiddleware
from app.models import HandshakeRequest, HandshakeResponse, ProtectedResponse
from app.session_repository import SessionRepository

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

crypto_service = HybridCryptoService(kem_alg="ML-KEM-768")
session_repository = SessionRepository()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await session_repository.initialize()
    yield
    await session_repository.close()


app = FastAPI(title="PQC Secure REST API Demo", version="1.0.0", lifespan=lifespan)
app.add_middleware(CryptoMiddleware, session_repository=session_repository)


class LogHub:
    """
    Простая шина логов для отправки событий на dashboard через WebSocket.
    """

    def __init__(self) -> None:
        self.connections: List[WebSocket] = []
        self.lock = asyncio.Lock()
        self.events: List[str] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self.lock:
            self.connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self.lock:
            if ws in self.connections:
                self.connections.remove(ws)

    async def broadcast(self, message: str) -> None:
        timestamp = dt.datetime.now().strftime("%H:%M:%S")
        payload = f"[{timestamp}] {message}"
        self.events.append(payload)
        self.events = self.events[-200:]
        dead = []
        async with self.lock:
            for ws in self.connections:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.connections.remove(ws)


log_hub = LogHub()
protected_requests_total = 0


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PQC Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <div class="max-w-6xl mx-auto p-6">
    <h1 class="text-3xl font-bold mb-2">Защищенный REST API (PQC + Hybrid)</h1>
    <p class="text-slate-300 mb-6">
      Мониторинг этапов: генерация ключей, ML-KEM handshake, вывод защищенных данных.
    </p>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
      <div class="rounded-xl border border-slate-700 bg-slate-900 p-4">
        <div class="text-xs text-slate-400">Handshake Requests</div>
        <div id="metric-handshakes" class="text-2xl font-bold mt-1">0</div>
      </div>
      <div class="rounded-xl border border-slate-700 bg-slate-900 p-4">
        <div class="text-xs text-slate-400">Protected Requests</div>
        <div id="metric-protected" class="text-2xl font-bold mt-1">0</div>
      </div>
      <div class="rounded-xl border border-slate-700 bg-slate-900 p-4">
        <div class="text-xs text-slate-400">Active Sessions</div>
        <div id="metric-sessions" class="text-2xl font-bold mt-1">0</div>
      </div>
      <div class="rounded-xl border border-slate-700 bg-slate-900 p-4">
        <div class="text-xs text-slate-400">WebSocket</div>
        <div id="status" class="text-sm inline-block mt-2 px-2 py-1 rounded bg-amber-600">connecting...</div>
      </div>
    </div>

    <div class="rounded-2xl border border-slate-700 bg-slate-900 p-4 mb-4">
      <h2 class="text-xl font-semibold mb-3">Этапы демонстрации</h2>
      <ol id="steps" class="grid md:grid-cols-5 gap-2 text-sm">
        <li class="rounded border border-slate-700 p-2">1) Клиент генерирует ML-KEM ключи</li>
        <li class="rounded border border-slate-700 p-2">2) Клиент отправляет handshake</li>
        <li class="rounded border border-slate-700 p-2">3) Сервер делает инкапсуляцию</li>
        <li class="rounded border border-slate-700 p-2">4) Формируется гибридный ключ</li>
        <li class="rounded border border-slate-700 p-2">5) Доступ к protected endpoint</li>
      </ol>
    </div>

    <div class="rounded-2xl border border-slate-700 bg-slate-900 p-4 mb-4">
      <h2 class="text-xl font-semibold mb-3">Сессии</h2>
      <div class="overflow-auto">
        <table class="w-full text-sm">
          <thead class="text-slate-400">
            <tr>
              <th class="text-left p-2">Session ID</th>
              <th class="text-left p-2">KEM</th>
              <th class="text-left p-2">Fingerprint</th>
              <th class="text-left p-2">Created (UTC)</th>
            </tr>
          </thead>
          <tbody id="sessions-body"></tbody>
        </table>
      </div>
    </div>

    <div class="rounded-2xl border border-slate-700 bg-slate-900 p-4">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-xl font-semibold">Live Logs</h2>
        <button id="clear-btn" class="text-xs px-2 py-1 rounded bg-slate-700 hover:bg-slate-600">очистить</button>
      </div>
      <pre id="logs" class="h-[360px] overflow-auto text-sm leading-6 whitespace-pre-wrap"></pre>
    </div>
  </div>

  <script>
    const logs = document.getElementById("logs");
    const status = document.getElementById("status");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/logs`);
    const metricHandshakes = document.getElementById("metric-handshakes");
    const metricProtected = document.getElementById("metric-protected");
    const metricSessions = document.getElementById("metric-sessions");
    const sessionsBody = document.getElementById("sessions-body");
    const steps = document.getElementById("steps").children;
    const clearBtn = document.getElementById("clear-btn");

    clearBtn.onclick = () => { logs.textContent = ""; };

    function markStep(index) {
      for (let i = 0; i < steps.length; i++) {
        steps[i].className = "rounded border border-slate-700 p-2";
      }
      if (index >= 0 && index < steps.length) {
        steps[index].className = "rounded border border-emerald-400 bg-emerald-900/20 p-2";
      }
    }

    async function refreshState() {
      try {
        const r = await fetch("/api/dashboard/state");
        if (!r.ok) return;
        const data = await r.json();
        metricHandshakes.textContent = data.handshake_requests_total;
        metricProtected.textContent = data.protected_requests_total;
        metricSessions.textContent = data.active_sessions;

        sessionsBody.innerHTML = "";
        for (const s of data.recent_sessions) {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td class="p-2 font-mono text-xs">${s.session_id}</td>
            <td class="p-2">${s.kem_algorithm}</td>
            <td class="p-2 font-mono">${s.key_fingerprint}</td>
            <td class="p-2">${s.created_at}</td>
          `;
          sessionsBody.appendChild(tr);
        }
      } catch (_) {}
    }

    ws.onopen = () => {
      status.textContent = "connected";
      status.className = "text-xs px-2 py-1 rounded bg-emerald-600";
    };

    ws.onclose = () => {
      status.textContent = "disconnected";
      status.className = "text-xs px-2 py-1 rounded bg-rose-700";
    };

    ws.onmessage = (event) => {
      const line = event.data;
      logs.textContent += line + "\\n";
      logs.scrollTop = logs.scrollHeight;

      if (line.includes("Генерация клиентских ключей")) markStep(0);
      if (line.includes("Получен запрос handshake")) markStep(1);
      if (line.includes("инкапсуляцию")) markStep(2);
      if (line.includes("гибридный")) markStep(3);
      if (line.includes("Доступ к защищенному endpoint")) markStep(4);

      refreshState();
    };

    refreshState();
    setInterval(refreshState, 3000);
  </script>
</body>
</html>
"""


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket) -> None:
    await log_hub.connect(ws)
    await ws.send_text("Dashboard подключен к потоку событий.")
    for event in log_hub.events[-30:]:
        await ws.send_text(event)
    try:
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        await log_hub.disconnect(ws)


@app.post("/api/handshake", response_model=HandshakeResponse)
async def handshake(payload: HandshakeRequest) -> HandshakeResponse:
    try:
        app.state.handshake_requests_total = getattr(app.state, "handshake_requests_total", 0) + 1
        await log_hub.broadcast("Генерация клиентских ключей завершена (со стороны клиента).")
        await log_hub.broadcast("Получен запрос handshake от клиента.")
        await log_hub.broadcast("Сервер выполняет ML-KEM инкапсуляцию...")
        await log_hub.broadcast("Сервер вычисляет классический X25519 shared secret...")

        session_id, pq_ciphertext, server_classic_pub = crypto_service.server_handshake(
            client_pq_public_key_hex=payload.pq_public_key,
            client_classic_public_key_hex=payload.classic_public_key,
        )
        state = crypto_service.sessions[session_id]
        await session_repository.save_session(
            session_id=session_id,
            raw_session_key=state.session_key,
            fingerprint=state.key_fingerprint,
            kem_algorithm=state.kem_algorithm,
            created_at=state.created_at,
        )

        await log_hub.broadcast(
            f"Handshake завершен. Сессия создана: {session_id}"
        )
        if session_repository.db_enabled:
            await log_hub.broadcast("Сессия сохранена в PostgreSQL (ключ зашифрован Fernet).")
        else:
            await log_hub.broadcast("Сессия сохранена (in-memory, ключ зашифрован Fernet).")
        await log_hub.broadcast("На сервере сформирован гибридный сессионный ключ.")
        return HandshakeResponse(
            session_id=session_id,
            pq_ciphertext=pq_ciphertext,
            server_classic_public_key=server_classic_pub,
        )
    except Exception as exc:
        await log_hub.broadcast(f"Ошибка handshake: {exc}")
        raise HTTPException(status_code=400, detail=f"Ошибка handshake: {exc}") from exc


@app.get("/api/protected/{session_id}", response_model=ProtectedResponse)
async def protected_data(session_id: str, request: Request) -> ProtectedResponse:
    global protected_requests_total
    header_session = getattr(request.state, "session_id", None)
    if header_session and header_session != session_id:
        raise HTTPException(status_code=401, detail="X-Session-ID не совпадает с идентификатором в URL")
    try:
        protected_requests_total += 1
        proof = crypto_service.get_proof(session_id)
        await log_hub.broadcast(f"Доступ к защищенному endpoint для сессии {session_id}.")
        await log_hub.broadcast("CryptoMiddleware: ответ зашифрован (AES-GCM).")
        return ProtectedResponse(
            session_id=session_id,
            message="Доступ предоставлен: защищенные данные получены.",
            proof=proof,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/protected/submit")
async def protected_submit(request: Request) -> dict:
    decrypted = getattr(request.state, "decrypted_data", None)
    if decrypted is None:
        raise HTTPException(status_code=400, detail="Отсутствует дешифрованная полезная нагрузка")
    session_id = request.state.session_id
    await log_hub.broadcast(f"Принят зашифрованный POST для сессии {session_id}.")
    return {
        "session_id": session_id,
        "message": "Полезная нагрузка успешно дешифрована middleware.",
        "received": decrypted,
    }


@app.get("/api/dashboard/state")
async def dashboard_state() -> dict:
    sessions = await session_repository.list_sessions(limit=10)
    return {
        "handshake_requests_total": getattr(app.state, "handshake_requests_total", 0),
        "protected_requests_total": protected_requests_total,
        "active_sessions": len(sessions),
        "recent_sessions": sessions[:10],
        "events_total": len(log_hub.events),
    }
