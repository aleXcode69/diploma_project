# Защищенный RESTful API с постквантовой криптографией

Демонстрационный проект для ВКР:
- `FastAPI` backend
- `ML-KEM-768` (Kyber) для постквантового обмена (`pqcrypto`)
- `X25519` для классической части
- гибридный сессионный ключ через `HKDF(PQ_secret || Classic_secret)`
- dashboard на Tailwind с live-логами, метриками и таблицей сессий
- `client.py` как эмулятор внешнего устройства

## Структура

- `app/main.py` — API, WebSocket-логи, dashboard
- `app/crypto.py` — логика гибридного handshake
- `app/models.py` — Pydantic-модели
- `client.py` — клиентский сценарий handshake

## Быстрый запуск (локально)

1. Создай и активируй venv:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

2. Установи зависимости:

```powershell
pip install -r requirements.txt
```

3. Запусти сервер:

```powershell
uvicorn app.main:app --reload
```

4. Открой dashboard:
- [http://127.0.0.1:8000](http://127.0.0.1:8000)

5. Запусти клиента в отдельном терминале:

```powershell
python client.py
```

После запуска клиента dashboard начнет показывать этапы handshake в реальном времени.

## Что показывать на защите (готовый сценарий)

1. Открыть `http://127.0.0.1:8000` и кратко показать блоки dashboard:
   - метрики запросов,
   - этапы криптопротокола,
   - таблицу сессий (ID, KEM, fingerprint),
   - поток live-логов.
2. Запустить `python client.py`.
3. Показать, как dashboard "оживает":
   - растет счетчик handshake/protected,
   - подсвечиваются этапы протокола,
   - появляется новая сессия в таблице,
   - в логах видны шаги ML-KEM + X25519 + гибридизация.
4. Завершить демонстрацию вызовом защищенного endpoint-а:
   - в клиенте приходит `Доступ предоставлен`,
   - на дашборде фиксируется событие доступа.

## Запуск через Docker

```powershell
docker compose up --build
```

И затем:

```powershell
python client.py --base-url http://127.0.0.1:8000
```

## Важно по зависимостям PQC

Проект использует `pqcrypto`, который обычно устанавливается на Windows без ручной сборки `liboqs`.
Если локальная установка не проходит, используй Docker-вариант (он наиболее стабильный для демонстрации на защите).
