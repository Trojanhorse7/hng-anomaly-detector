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
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>HNG anomaly detector</title>
<style>
:root {
  --bg0: #0a0c10;
  --bg1: #12151c;
  --card: #181c26;
  --line: #2a3140;
  --text: #e9eef5;
  --dim: #8a96a8;
  --accent: #4ad4b8;
  --accent2: #2b9e86;
  --warn: #e4b042;
  --bad: #e56b6b;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: radial-gradient(1200px 600px at 10% -10%, #1a222e 0%, var(--bg0) 55%);
  color: var(--text);
  line-height: 1.45;
}
header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1.1rem 1.4rem;
  border-bottom: 1px solid var(--line);
  background: linear-gradient(180deg, rgba(24,28,38,.95) 0%, transparent);
  backdrop-filter: blur(8px);
}
header h1 {
  margin: 0;
  font-size: 1.2rem;
  font-weight: 650;
  letter-spacing: -0.03em;
}
.badge {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  padding: 0.35rem 0.75rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  color: var(--dim);
  background: rgba(255,255,255,.03);
}
.badge.ok { color: var(--accent); border-color: var(--accent2); box-shadow: 0 0 0 1px rgba(74,212,184,.15); }
.badge.warn { color: var(--warn); border-color: #7a6228; }
main {
  padding: 1.2rem 1.4rem 2rem;
  max-width: 1080px;
  margin: 0 auto;
}
.alert {
  display: none;
  padding: 0.8rem 1rem;
  border-radius: 10px;
  margin-bottom: 1rem;
  font-size: 0.88rem;
  background: #29151a;
  border: 1px solid #5c3038;
  color: #f0b8c0;
}
.alert.show { display: block; }
.kpis {
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fill, minmax(148px, 1fr));
  margin-bottom: 1.1rem;
}
.kpi {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.85rem 1rem;
  box-shadow: 0 8px 24px rgba(0,0,0,.22);
}
.kpi .k { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--dim); }
.kpi .v { font-family: var(--mono); font-size: 1.28rem; font-weight: 650; margin-top: 0.2rem; }
.kpi .v span.unit { font-size: 0.82rem; font-weight: 500; color: var(--dim); margin-left: 0.12rem; }
.split {
  display: grid;
  gap: 1rem;
}
@media (min-width: 800px) {
  .split { grid-template-columns: 1fr 1.1fr; align-items: start; }
}
.panel {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem 1.1rem;
  margin-bottom: 1rem;
  box-shadow: 0 8px 24px rgba(0,0,0,.18);
}
.panel h2 {
  margin: -.1rem 0 0.75rem;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.09em;
  color: var(--dim);
}
table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
th, td { text-align: left; padding: 0.5rem 0.55rem; border-bottom: 1px solid var(--line); }
th {
  color: var(--dim);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
td { font-family: var(--mono); font-size: 0.8rem; }
tr:last-child td { border-bottom: none; }
.tag {
  display: inline-block;
  font-size: 0.62rem;
  font-weight: 700;
  padding: 0.18rem 0.45rem;
  border-radius: 5px;
  letter-spacing: 0.03em;
  text-transform: uppercase;
}
.tag-perm { background: #362022; color: #f0a0a8; }
.tag-temp { background: #252b1c; color: #c8d870; }
.row { display: grid; grid-template-columns: 1fr 5fr auto; gap: 0.55rem; align-items: center; margin-bottom: 0.42rem; }
.row:last-child { margin-bottom: 0; }
.row .ip {
  font-family: var(--mono);
  font-size: 0.78rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.track { height: 7px; background: var(--bg0); border-radius: 6px; overflow: hidden; }
.fill { height: 100%; border-radius: 6px; background: linear-gradient(90deg, var(--accent2), var(--accent)); min-width: 2px; }
.cnt { font-family: var(--mono); font-size: 0.76rem; color: var(--dim); text-align: right; min-width: 2.2rem; }
.muted { color: var(--dim); font-size: 0.88rem; padding: 0.35rem 0; }
footer {
  margin-top: 1.25rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  font-size: 0.76rem;
  color: var(--dim);
}
footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }
</style>
</head>
<body>
<header>
  <h1>HNG anomaly detector</h1>
  <span class="badge" id="st">Connecting…</span>
</header>
<main>
  <div class="alert" id="err"></div>
  <div id="root"></div>
  <footer>
    Live metrics · <a href="/api/state" target="_blank" rel="noopener">raw JSON</a>
  </footer>
</main>
<script>
(function () {
  const st = document.getElementById('st');
  const root = document.getElementById('root');
  const errEl = document.getElementById('err');
  let pollTimer = null;

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function fmtUptime(sec) {
    if (sec == null || Number.isNaN(sec)) return '—';
    sec = Number(sec);
    if (sec < 60) return sec.toFixed(0) + ' s';
    const m = Math.floor(sec / 60);
    if (m < 60) return m + ' m ' + Math.floor(sec % 60) + ' s';
    const h = Math.floor(m / 60);
    return h + ' h ' + (m % 60) + ' m';
  }
  function fmtNum(n, d) {
    if (n == null || Number.isNaN(n)) return '—';
    return Number(n).toFixed(d);
  }
  function fmtUnban(uat, permanent) {
    if (permanent) return '—';
    if (uat == null) return '—';
    const t = Number(uat) * 1000;
    if (Number.isNaN(t)) return '—';
    try {
      return new Date(t).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' });
    } catch (e) { return '—'; }
  }
  function setBadge(text, cls) {
    st.textContent = text;
    st.className = 'badge' + (cls ? ' ' + cls : '');
  }
  function showErr(m) { errEl.textContent = m; errEl.classList.add('show'); }
  function hideErr() { errEl.classList.remove('show'); }

  function render(j) {
    hideErr();
    const win = Number(j.window_seconds) || 60;
    const rps = j.global_rps != null ? fmtNum(j.global_rps, 3) : '—';
    const top = (j.top_source_ips || []).slice().sort(function (a, b) {
      return (b.count || 0) - (a.count || 0);
    });
    const maxC = top.length ? Math.max.apply(null, top.map(function (t) { return t.count || 0; })) : 1;

    let bars = '';
    if (!top.length) bars = '<p class="muted">No requests in the sliding window.</p>';
    else {
      top.forEach(function (row) {
        const c = row.count || 0;
        const pct = maxC ? Math.round((c / maxC) * 100) : 0;
        bars += '<div class="row">' +
          '<span class="ip" title="' + esc(row.ip) + '">' + esc(row.ip) + '</span>' +
          '<div class="track"><div class="fill" style="width:' + pct + '%"></div></div>' +
          '<span class="cnt">' + esc(String(c)) + '</span></div>';
      });
    }

    let banRows = '';
    const banned = j.banned || [];
    if (!banned.length) banRows = '<tr><td colspan="4" class="muted">No active bans.</td></tr>';
    else {
      banned.forEach(function (b) {
        var perm = !!b.permanent;
        banRows += '<tr><td>' + esc(b.ip) + '</td><td>' +
          (perm
            ? '<span class="tag tag-perm">Permanent</span>'
            : '<span class="tag tag-temp">Temp</span>') +
          '</td><td>' + esc(String(b.bans_total != null ? b.bans_total : '—')) +
          '</td><td>' + esc(fmtUnban(b.unban_at, perm)) + '</td></tr>';
      });
    }

    var em = j.effective_mean != null ? fmtNum(j.effective_mean, 4) : '—';
    var es = j.effective_std != null ? fmtNum(j.effective_std, 4) : '—';
    var ern = j.error_mean != null ? fmtNum(j.error_mean, 4) : '—';

    root.innerHTML =
      '<div class="kpis">' +
        '<div class="kpi"><div class="k">Uptime</div><div class="v">' + esc(fmtUptime(j.uptime_s)) + '</div></div>' +
        '<div class="kpi"><div class="k">Events</div><div class="v">' + esc(String(j.events != null ? j.events : '—')) + '</div></div>' +
        '<div class="kpi"><div class="k">Global RPS</div><div class="v">' + esc(rps) + '<span class="unit">/s</span></div></div>' +
        '<div class="kpi"><div class="k">Window</div><div class="v">' + esc(String(win)) + '<span class="unit">s</span></div></div>' +
        '<div class="kpi"><div class="k">CPU</div><div class="v">' + esc(fmtNum(j.cpu_percent, 1)) + '<span class="unit">%</span></div></div>' +
        '<div class="kpi"><div class="k">Memory</div><div class="v">' + esc(fmtNum(j.memory_percent, 1)) + '<span class="unit">%</span></div></div>' +
      '</div>' +
      '<div class="split">' +
        '<div class="panel"><h2>Baseline</h2><table><tr><th>Metric</th><th>Value</th></tr>' +
        '<tr><td>Effective mean</td><td>' + esc(em) + '</td></tr>' +
        '<tr><td>Effective σ</td><td>' + esc(es) + '</td></tr>' +
        '<tr><td>Error mean</td><td>' + esc(ern) + '</td></tr></table></div>' +
        '<div class="panel"><h2>Top source IPs</h2>' + bars + '</div>' +
      '</div>' +
      '<div class="panel"><h2>Active bans</h2><table><thead><tr><th>IP</th><th>Tier</th><th>Total bans</th><th>Unban (local)</th></tr></thead>' +
      '<tbody>' + banRows + '</tbody></table></div>';
  }

  async function refreshViaHttp() {
    try {
      const r = await fetch('/api/state', { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      render(await r.json());
    } catch (e) { showErr(String(e)); }
  }

  function startPolling(reason) {
    if (pollTimer) return;
    setBadge(reason, 'warn');
    refreshViaHttp();
    pollTimer = setInterval(refreshViaHttp, 2500);
  }

  function connectWs() {
    const effectivePort = Number(location.port) || (location.protocol === 'https:' ? 443 : 80);
    const useTlsWs = location.protocol === 'https:' && effectivePort !== 8080;
    const wsScheme = useTlsWs ? 'wss' : 'ws';
    const portSeg = location.port !== '' ? ':' + location.port : '';
    const url = wsScheme + '://' + location.hostname + portSeg + '/ws';
    if (typeof console !== 'undefined' && console.debug)
      console.debug('[hng-dashboard] WebSocket url:', url);

    const ws = new WebSocket(url);
    let opened = false;

    function bail() {
      if (pollTimer || opened) return;
      startPolling('HTTP polling');
    }

    ws.onopen = function () {
      opened = true;
      setBadge('Live · WebSocket', 'ok');
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    };
    ws.onmessage = function (ev) {
      try { render(JSON.parse(ev.data)); }
      catch (e) { showErr(String(e)); }
    };
    ws.onerror = function () { if (!opened) bail(); };
    ws.onclose = function () {
      if (!opened) bail();
      else { setBadge('Reconnecting…', 'warn'); startPolling('HTTP polling'); }
    };
    setTimeout(function () { if (!opened && !pollTimer) bail(); }, 3000);
  }

  root.innerHTML = '<p class="muted">Loading…</p>';
  connectWs();
})();
</script>
</body>
</html>
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
        try:
            await websocket.accept()
        except Exception:
            log.exception("websocket accept failed")
            raise
        try:
            while True:
                try:
                    payload = await asyncio.to_thread(get_state)
                    await websocket.send_json(payload)
                except Exception:
                    log.exception("websocket send failed (metrics payload)")
                    break
                await asyncio.sleep(push_interval_s)
        except WebSocketDisconnect:
            log.debug("websocket client disconnected")
        except Exception:
            log.exception("websocket loop exited")

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
