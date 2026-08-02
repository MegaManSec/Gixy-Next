(() => {
  const root = document.querySelector("[data-gixy-scan]");
  if (!root) return;

  const ta = document.getElementById("gixyConf");
  const runBtn = document.getElementById("gixyRun");
  const statusEl = document.getElementById("gixyStatus");
  const summaryEl = document.getElementById("gixySummary");
  const filtersEl = document.getElementById("gixyFilters");
  const findingsEl = document.getElementById("gixyFindings");
  const exampleBtn = document.getElementById("gixyExample");

  const PYODIDE_BASE = "https://cdn.jsdelivr.net/pyodide/v0.29.0/full/";
  const PYODIDE_MOD = PYODIDE_BASE + "pyodide.mjs";

  const WHEEL_URL = new URL("/extra/gixy_next-0.0.0-py3-none-any.whl", window.location.origin).href;

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION", "UNKNOWN"];

  const state = {
    initPromise: null,
    pyodide: null,
    findings: [],
    filters: {
      severities: new Set(), // empty = all
    },
  };

  const EXAMPLE_CONF = `# configuration file /etc/nginx/nginx.conf:
user  nginx;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log  off warn;

    sendfile on;
    keepalive_timeout 65;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types {
    text/html                             html htm shtml;
    text/css                              css;
    application/javascript                js;
}

# configuration file /etc/nginx/conf.d/gzip.conf:
gzip on;
gzip_comp_level 5;
gzip_types text/plain text/css application/json application/javascript;

# configuration file /etc/nginx/sites-enabled/example.conf:
upstream app_backend {
    server example.com:3000;
}

server {
    listen 80;
    server_name example.test;

    location /healthz {
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }

    location / {
        if ($url = "/loc") {
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_pass http://app_backend/;
        }
    }
}
`;

  if (exampleBtn && ta) {
    exampleBtn.addEventListener("click", () => {
      ta.value = EXAMPLE_CONF;
      ta.focus();
      ta.selectionStart = ta.selectionEnd = ta.value.length;
    });
  }

  function setStatus(text) {
    statusEl.textContent = text || "";
  }

  function stableId(f) {
    const plugin = String(f.plugin || "");
    const path = String(f.path || f.file || "");
    const line = String(f.line ?? "");
    const summary = String(f.summary || "");
    return `${plugin}|${path}|${line}|${summary}`;
  }

  function normSeverity(s) {
    const v = String(s || "").toUpperCase();
    if (severityOrder.includes(v)) return v;
    return v ? v : "UNKNOWN";
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function severityBadgeHtml(sev) {
    return `<span class="gixy-badge">${escapeHtml(sev)}</span>`;
  }

  function makeChip(label, pressed, onClick, title) {
    const el = document.createElement("span");
    el.className = "gixy-chip";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("aria-pressed", pressed ? "true" : "false");
    if (title) el.title = title;
    el.textContent = label;

    el.addEventListener("click", onClick);
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") onClick();
    });

    return el;
  }

  function render() {
    const all = state.findings;

    const sevFilter = state.filters.severities;
    const filtered = all.filter((f) => {
      return sevFilter.size === 0 || sevFilter.has(f.__severity);
    });

    const counts = new Map();
    for (const s of severityOrder) counts.set(s, 0);
    for (const f of all) counts.set(f.__severity, (counts.get(f.__severity) || 0) + 1);

    summaryEl.hidden = false;
    summaryEl.replaceChildren();

    summaryEl.appendChild(document.createTextNode(`Findings: ${all.length}`));

    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"]) {
      const n = counts.get(sev) || 0;
      if (!n) continue;

      const pressed = sevFilter.has(sev);
      summaryEl.appendChild(
        makeChip(`${sev}: ${n}`, pressed, () => {
          if (sevFilter.has(sev)) sevFilter.delete(sev);
          else sevFilter.add(sev);
          render();
        })
      );
    }
    if (all.length > 0) {
      summaryEl.appendChild(
        makeChip(
          "Clear filters",
          false,
          () => {
            sevFilter.clear();
            render();
          },
          "Show all severities"
        )
      );
    }

    if (filtersEl) {
      filtersEl.hidden = true;
      filtersEl.replaceChildren();
    }

    findingsEl.replaceChildren();

    if (filtered.length === 0) {
      const p = document.createElement("p");
      p.className = "gixy-meta";
      p.textContent = all.length ? "No findings match the current filters." : "No findings.";
      findingsEl.appendChild(p);
      return;
    }

    for (const f of filtered) {
      const d = document.createElement("details");

      const file = f.path || f.file || "";
      const line = f.line != null ? `${f.line}` : "";
      const sev = f.__severity;

      const s = document.createElement("summary");
      s.innerHTML = `
        <div class="gixy-row1">
          ${severityBadgeHtml(sev)}
          <strong>${escapeHtml(f.summary || "(no summary)")}</strong>
          <span class="gixy-meta">Line ${escapeHtml(line)}.</span>
        </div>
        <div class="gixy-meta">${escapeHtml(f.reason || "")}</div>
      `;

      const body = document.createElement("div");
      body.innerHTML = `
        ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ""}
        ${f.config ? `<pre class="gixy-code"><code>${escapeHtml(f.config)}</code></pre>` : ""}
        <div class="gixy-actions2">
          ${f.reference ? `Reference: <a class="gixy-link" href="${escapeHtml(f.reference)}" target="_blank" rel="noopener">[${escapeHtml(f.plugin || "")}]</a>` : ""}
        </div>
      `;

      d.appendChild(s);
      d.appendChild(body);
      findingsEl.appendChild(d);
    }
  }

  function safeParseJson(text) {
    const t = String(text || "").trim();
    if (!t) return null;

    try {
      return JSON.parse(t);
    } catch {}

    const first = t.indexOf("[");
    const last = t.lastIndexOf("]");
    if (first >= 0 && last > first) {
      const slice = t.slice(first, last + 1);
      try {
        return JSON.parse(slice);
      } catch {}
    }

    return null;
  }

  async function initPyodideOnce() {
    if (state.initPromise) return state.initPromise;

    state.initPromise = (async () => {
      const mod = await import(PYODIDE_MOD);
      const pyodide = await mod.loadPyodide({ indexURL: PYODIDE_BASE });

      await pyodide.loadPackage("micropip");
      await pyodide.runPythonAsync(`
import micropip
await micropip.install("${WHEEL_URL}")
      `);

      state.pyodide = pyodide;
      return pyodide;
    })();

    return state.initPromise;
  }

  async function runScan() {
    findingsEl.replaceChildren();
    summaryEl.hidden = true;
    if (filtersEl) filtersEl.hidden = true;

    if (exampleBtn) exampleBtn.remove();

    runBtn.disabled = true;

    try {
      setStatus("Loading...");
      const py = await initPyodideOnce();

      setStatus("Scanning...");

      const workDir = "/work";
      try { py.FS.mkdir(workDir); } catch {}

      const inputPath = workDir + "/stdin.conf";
      const raw = String(ta.value || "");
      const text = raw.endsWith("\n") ? raw : raw + "\n";
      py.FS.writeFile(inputPath, text);

      // Capture stdout so JSON parsing is clean.
      const out = await py.runPythonAsync(`
import sys, runpy, io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    sys.argv = ["gixy", "-f", "json", "${inputPath}"]
    try:
        runpy.run_module("gixy.cli", run_name="__main__")
    except SystemExit:
        pass
buf.getvalue()
      `);

      const parsed = safeParseJson(out);
      if (!parsed) {
        const pre = document.createElement("pre");
        pre.className = "gixy-code";
        pre.textContent = String(out || "(no output)");
        findingsEl.appendChild(pre);
        return;
      }

      const arr = Array.isArray(parsed) ? parsed : [];
      state.findings = arr
        .map((f) => {
          const ff = f && typeof f === "object" ? f : {};
          const id = stableId(ff);
          return {
            ...ff,
            __id: id,
            __severity: normSeverity(ff.severity),
          };
        })
        .sort((a, b) => {
          return severityOrder.indexOf(a.__severity) - severityOrder.indexOf(b.__severity);
        });

      render();
    } catch (e) {
      const pre = document.createElement("pre");
      pre.className = "gixy-code";
      pre.textContent = String(e);
      findingsEl.appendChild(pre);
    } finally {
      setStatus("");
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener("click", runScan);
})();
