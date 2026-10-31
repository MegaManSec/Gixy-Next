(() => {
  const root = document.querySelector("[data-gixy-scan]");
  if (!root) return;

  const ta = document.getElementById("gixyConf");
  const runBtn = document.getElementById("gixyRun");
  const statusEl = document.getElementById("gixyStatus");
  const noticesEl = document.getElementById("gixyNotices");
  const summaryEl = document.getElementById("gixySummary");
  const filtersEl = document.getElementById("gixyFilters");
  const findingsEl = document.getElementById("gixyFindings");
  const exampleBtn = document.getElementById("gixyExample");

  const PYODIDE_BASE = "https://cdn.jsdelivr.net/pyodide/v0.29.0/full/";
  const PYODIDE_MOD = PYODIDE_BASE + "pyodide.mjs";

  const WHEEL_URL = new URL("/extra/gixy_next-0.0.0-py3-none-any.whl", window.location.origin).href;
  const PYPI_PINS = [
    "configargparse==1.9.0",
    "crossplane==0.5.8",
    "filelock==4.2.5",
    "requests-file==3.0.1",
    "tldextract==5.4.0",
  ];
  const ISSUES_URL = "https://github.com/MegaManSec/Gixy-Next/issues/new";

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

  const reportLink = `<a href="${ISSUES_URL}" target="_blank" rel="noopener">report it on GitHub</a>`;

  function showNotice(type, title, bodyHtml, details) {
    const box = document.createElement("div");
    box.className = `admonition ${type}`;
    box.setAttribute("role", type === "success" ? "status" : "alert");
    box.innerHTML = `<p class="admonition-title">${escapeHtml(title)}</p>${bodyHtml}`;
    if (details) {
      const d = document.createElement("details");
      d.className = "gixy-details";
      d.innerHTML = `<summary>Technical details</summary><pre><code>${escapeHtml(details)}</code></pre>`;
      box.appendChild(d);
    }
    noticesEl.appendChild(box);
  }

  function problemsHtml(problems, inputPath) {
    const items = problems.map((p) => {
      const file = p.file && p.file !== inputPath ? p.file : "";
      const line = p.line != null ? (file ? `${file}:${p.line}` : `Line ${p.line}`) : file;
      const where = [
        line && escapeHtml(line),
        p.directive && `<code>${escapeHtml(p.directive)}</code>`,
        p.plugin && `plugin <code>${escapeHtml(p.plugin)}</code>`,
      ].filter(Boolean);
      const meta = where.length ? `<span class="gixy-meta">${where.join(" · ")}</span>` : "";
      return `<li>${meta}${escapeHtml(p.message)}</li>`;
    });
    return `<ul class="gixy-problems">${items.join("")}</ul>`;
  }

  function showOutcome(outcome, inputPath) {
    const malformed = outcome.problems.filter((p) => p.kind === "malformed");
    const internal = outcome.problems.filter((p) => p.kind !== "malformed");

    if (malformed.length) {
      showNotice(
        "warning",
        "Couldn't analyze all of this configuration",
        `${problemsHtml(malformed, inputPath)}
        <p>Findings in these parts may be missing. Gixy-Next is a security linter, not a syntax checker, so validate the configuration with <code>nginx -t</code>.</p>`
      );
    }
    if (internal.length) {
      showNotice(
        "bug",
        "Gixy-Next hit an internal error",
        `${problemsHtml(internal, inputPath)}
        <p>This is a bug in Gixy-Next, not a problem with your configuration, and some findings may be missing. Please ${reportLink}.</p>`
      );
    }
    if (outcome.exit_code === 0 && state.findings.length === 0) {
      showNotice("success", "No issues found", "<p>Gixy-Next found nothing to report in this configuration.</p>");
    }
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

    findingsEl.replaceChildren();
    summaryEl.replaceChildren();
    summaryEl.hidden = all.length === 0;
    if (all.length === 0) return;

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

    if (filtersEl) {
      filtersEl.hidden = true;
      filtersEl.replaceChildren();
    }

    if (filtered.length === 0) {
      const p = document.createElement("p");
      p.className = "gixy-meta";
      p.textContent = "No findings match the current filters.";
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
await micropip.install("${WHEEL_URL}", constraints=${JSON.stringify(PYPI_PINS)})
      `);

      state.pyodide = pyodide;
      return pyodide;
    })();

    return state.initPromise;
  }

  async function runScan() {
    noticesEl.replaceChildren();
    findingsEl.replaceChildren();
    summaryEl.hidden = true;
    if (filtersEl) filtersEl.hidden = true;

    if (exampleBtn) exampleBtn.remove();

    runBtn.disabled = true;

    let loaded = false;
    try {
      setStatus("Loading...");
      const py = await initPyodideOnce();
      loaded = true;

      setStatus("Scanning...");

      const inputPath = "/nginx.conf";
      const raw = String(ta.value || "");
      const text = raw.endsWith("\n") ? raw : raw + "\n";
      py.FS.writeFile(inputPath, text);

      const out = await py.runPythonAsync(`
import sys, runpy, io, contextlib, json
import gixy.cli.main as cli
buf, errors = io.StringIO(), io.StringIO()
exit_code, problems = 0, []
emit = cli._emit_diagnostics
def capture(diagnostics, debug=False):
    problems.extend(rec for _, rec in diagnostics)
    emit(diagnostics, debug)
cli._emit_diagnostics = capture
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errors):
    sys.argv = ["gixy", "-f", "json", "${inputPath}"]
    try:
        runpy.run_module("gixy.cli", run_name="__main__")
    except SystemExit as exc:
        exit_code = exc.code
    finally:
        cli._emit_diagnostics = emit
fields = ("kind", "message", "file", "line", "directive", "plugin")
unique = dict.fromkeys(tuple(getattr(rec, f) for f in fields) for rec in problems)
json.dumps({
    "report": buf.getvalue(),
    "diagnostics": errors.getvalue(),
    "problems": [dict(zip(fields, key)) for key in unique],
    "exit_code": exit_code,
})
      `);

      const outcome = JSON.parse(out);
      const parsed = safeParseJson(outcome.report);
      if (!Array.isArray(parsed) || (outcome.exit_code > 1 && outcome.problems.length === 0)) {
        throw new Error(outcome.diagnostics || outcome.report || "The scanner produced no report.");
      }

      state.findings = parsed
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

      showOutcome(outcome, inputPath);
      render();
    } catch (e) {
      if (loaded) {
        showNotice(
          "bug",
          "The scanner stopped unexpectedly",
          `<p>Press Run to try again. If it keeps happening, please ${reportLink}.</p>`,
          String(e)
        );
      } else {
        state.initPromise = null;
        showNotice(
          "failure",
          "Couldn't load the scanner",
          "<p>The scanner runs in your browser and downloads its runtime from cdn.jsdelivr.net. Check your connection and any content blockers, then press Run to try again.</p>",
          String(e)
        );
      }
    } finally {
      setStatus("");
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener("click", runScan);
})();
