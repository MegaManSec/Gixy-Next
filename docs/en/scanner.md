---
title: "Online In-Browser Scanner"
description: "In-browser gixy-next scanner for Nginx configs, powered by WebAssembly. Runs locally in your browser (no uploads). For best results, scan nginx -T output to include all includes."
---

???+ info "In-browser Scanner"
    This page is the in-browser build of Gixy-Next. It runs entirely in your browser using WebAssembly, and your config is analyzed locally; nothing is uploaded to any server.

    !!! tip "Config Format Tip"
        For the best results, scan the output of `nginx -T` since it expands all `include` directives into a single effective config. See [Nginx -T Live Configuration Dumps](https://gixy.io/nginx-config-dump) for more details.

<div class="gixy-scan" data-gixy-scan>
  <div class="gixy-scan__controls">
    <textarea
      id="gixyConf"
      class="gixy-textarea"
      rows="10"
      placeholder="Paste nginx config here..."
      spellcheck="false"
    ></textarea>

    <div class="gixy-actions">
      <button id="gixyRun" class="md-button md-button--primary" type="button">Run</button>
      <button id="gixyExample" class="md-button" type="button">Use example</button>
      <span id="gixyStatus" class="gixy-status"></span>
    </div>
  </div>

  <div id="gixyNotices" class="gixy-notices"></div>
  <div id="gixySummary" class="gixy-summary" hidden></div>
  <div id="gixyFilters" class="gixy-filters" hidden></div>
  <div id="gixyFindings" class="gixy-findings"></div>
</div>
