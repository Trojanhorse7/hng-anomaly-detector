"""Dashboard: FastAPI + WebSocket push (≤3s). GET /api/state kept for scripts / health."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from starlette.websockets import WebSocketDisconnect

log = logging.getLogger(__name__)

HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>HNG detector</title>
<style>
body{font-family:system-ui,sans-serif;margin:1rem;background:#111;color:#eee}
pre{background:#222;padding:1rem;overflow:auto;font-size:13px}
h1{font-size:1.1rem}
.status{color:#888;font-size:12px;margin-bottom:0.5rem}
</style></head><body>
<h1>Detector metrics</h1>
<p class="status" id="st">connecting…</p>
<pre id="o">loading…</pre>
<script>
const st = document.getElementById('st');
const o = document.getElementById('o');
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const url = proto + '//' + location.host + '/ws';
function connect(){
  const ws = new WebSocket(url);
  ws.onopen = () => { st.textContent = 'live (WebSocket)'; };
  ws.onmessage = (ev) => {
    try {
      const j = JSON.parse(ev.data);
      o.textContent = JSON.stringify(j, null, 2);
    } catch (e) { o.textContent = String(e); }
  };
  ws.onerror = () => { st.textContent = 'WebSocket error — retrying…'; };
  ws.onclose = () => {
    st.textContent = 'disconnected — reconnecting…';
    setTimeout(connect, 2000);
  };
}
connect();
</script>
</body></html>
"""


def build_state_json(
    *,
    win: Any,
    bl: Any,
    ban_mgr: Any,
    metrics: Any,
    window_s: float,
) -> dict[str, Any]:
    import psutil

    br = bl.last if bl else None
    top = win.top_source_ips(10)
    return {
        "uptime_s": round(metrics.uptime_s(), 1),
        "events": metrics.event_count,
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "global_rps": win.global_rps(),
        "window_seconds": window_s,
        "effective_mean": br.effective_mean if br else None,
        "effective_std": br.effective_std if br else None,
        "error_mean": br.error_effective_mean if br else None,
        "banned": ban_mgr.list_for_dashboard(),
        "top_source_ips": [{"ip": a, "count": b} for a, b in top],
    }


def create_app(
    get_state: Callable[[], dict[str, Any]],
    push_interval_s: float,
) -> FastAPI:
    app = FastAPI(title="HNG anomaly detector", version="1.0")

    @app.get("/api/state")
    def api_state() -> dict[str, Any]:
        return get_state()

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return HTML

    @app.websocket("/ws")
    async def metrics_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            while True:
                payload = await asyncio.to_thread(get_state)
                await websocket.send_json(payload)
                await asyncio.sleep(push_interval_s)
        except WebSocketDisconnect:
            pass

    return app


def start_dashboard(
    host: str,
    port: int,
    get_state: Callable[[], dict[str, Any]],
    *,
    push_interval_s: float = 2.5,
) -> None:
    app = create_app(get_state, push_interval_s)

    def _run() -> None:
        uvicorn.run(
            app,
            host=host,
            port=int(port),
            log_level="warning",
            access_log=False,
        )

    threading.Thread(target=_run, name="fastapi-dashboard", daemon=True).start()
    log.info(
        "dashboard FastAPI http://%s:%s/ (ws /ws, json /api/state, push every %.1fs)",
        host,
        port,
        push_interval_s,
    )
