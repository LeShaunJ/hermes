// hermes operator console — custom client logic that sits alongside
// htmx 2.x + idiomorph.  htmx handles every hx-*, hx-swap-oob,
// hx-target, etc.; this file does the project-specific bits htmx does
// not know about:
//
//   - adds Hx-Indent / Hx-Group headers derived from the source row's
//     CSS class so server-side row swaps preserve tree nesting,
//   - tracks image ids the current tab just acted on so the SSE
//     handler can skip the redundant refresh the inline OOB already
//     covered (the click-spam flicker fix),
//   - subscribes to /events (SSE) and dispatches each event type to
//     the right refresh primitive (row, repo tbody, image-detail
//     section), including filter-aware row removal,
//   - tree expand/collapse with localStorage persistence,
//   - copy-to-clipboard buttons.
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function base() { return document.body.dataset.base || ""; }

  // Default every swap to idiomorph ("morph" extension on <body>) so
  // SSE-triggered tbody / row refreshes diff the existing DOM rather
  // than destroying and recreating it — preserving expand state and
  // avoiding the "rebuild flash" between two back-to-back updates.
  if (window.htmx && htmx.config) {
    htmx.config.defaultSwapStyle = "morph";
  }

  // ── Local-action dedup ────────────────────────────────────────────────
  // A click on /images/{id}/<verb> returns inline OOB swaps that update
  // the row + ancestor cells.  Postgres NOTIFY also broadcasts that
  // event to every tab over SSE — *including* the originator.  Without
  // dedup the originator does the OOB swap and then immediately
  // refetches the whole repo tbody from the SSE handler, which is what
  // the user sees as flicker when clicking rapidly.  Mark the image id
  // here, gate the SSE handler against the mark, expire after a TTL.
  var localActionTTL = 1500; // ms — outlasts NOTIFY round-trip on a
                             // loopback compose stack without swallowing
                             // a legitimate follow-up event.
  var localActions = Object.create(null);
  function markLocalAction(id) {
    if (!id) return;
    localActions[id] = Date.now() + localActionTTL;
  }
  function isLocalEcho(id) {
    var until = localActions[id];
    if (!until) return false;
    if (Date.now() > until) { delete localActions[id]; return false; }
    return true;
  }
  var actionPathRE = /\/images\/(\d+)\/(scan|approve|reject|rescind|fetch)$/;

  // ── htmx:configRequest ────────────────────────────────────────────────
  // htmx already sends HX-Request, HX-Current-URL, HX-Target, HX-Trigger
  // on every request.  We add two custom headers so the server-side
  // partial knows where this row lives in the tree (level-1/2/3 +
  // its parent group) and can render the swap response with the same
  // nesting it had before, and we tag the image id so the SSE listener
  // can dedup the echo.
  document.body.addEventListener("htmx:configRequest", function (e) {
    var src = e.detail.elt;
    var row = src && src.closest && src.closest("tr");
    if (row) {
      var indent = "0";
      if (row.classList.contains("tree-lvl-3")) indent = "2";
      else if (row.classList.contains("tree-lvl-2")) indent = "1";
      e.detail.headers["Hx-Indent"] = indent;
      var grp = row.getAttribute("data-group");
      if (grp) e.detail.headers["Hx-Group"] = grp;
    }
    var m = actionPathRE.exec(e.detail.path || "");
    if (m) markLocalAction(parseInt(m[1], 10));
  });

  // ── SSE-driven row refreshes ──────────────────────────────────────────
  // Action-driven updates carry their own row + OOB ancestor swaps
  // back inline, so the listener below handles the cross-tab path:
  // events emitted by the gateway, the CLI, or another browser tab.
  var rowRefreshEvents = {
    scan: 1, scan_error: 1, fetch: 1, fetch_error: 1,
    approve: 1, reject: 1, rescind: 1,
    validate_voided: 1, validate_adopted: 1
  };
  var repoRefreshEvents = {
    validate_denied: 1, validate_adopted: 1
  };

  // refreshElement fetches html and hands it to htmx so OOB and target
  // swaps go through htmx's parser-aware fragment processing instead
  // of any home-grown logic.  Swap style defaults to "morph" so DOM
  // identity is preserved across refreshes — child rows stay in place
  // and only the changed cells repaint.  410 Gone removes the target
  // outright — server-side filter-aware dispatch uses this to drop a
  // row when the new state no longer passes the page's filter.
  function refreshElement(target, url, swapStyle) {
    if (!target || !url) return;
    fetch(url, {
      headers: { "HX-Request": "true", "HX-Current-URL": window.location.href },
      credentials: "same-origin"
    })
      .then(function (r) {
        if (r.status === 410) { target.remove(); return null; }
        return r.ok ? r.text() : null;
      })
      .then(function (html) {
        if (!html || !html.trim()) return;
        if (window.htmx && htmx.swap) {
          htmx.swap(target, html, { swapStyle: swapStyle || "morph" });
        }
      })
      .catch(function () { /* leave the DOM alone on transient failure */ });
  }

  function refreshRow(id) {
    var row = document.getElementById("image-" + id);
    if (!row) return;
    refreshElement(row, base() + "/images/" + id + "/row");
  }

  function refreshRepoTbody(rowID) {
    var tbody = document.getElementById("tbody-" + rowID);
    if (!tbody) return;
    refreshElement(tbody, tbody.getAttribute("data-refresh"));
  }

  function refreshDetail(id) {
    var section = document.getElementById("image-detail");
    if (!section || section.dataset.imageId !== String(id)) return;
    refreshElement(section, base() + "/images/" + id + "/detail", "morph:innerHTML");
  }

  // refreshAncestorRepo walks up the row's data-group chain to the
  // repo level and refreshes that whole <tbody>.  The tbody is the
  // single, well-defined boundary container, so refreshing it can
  // never leave orphan child rows behind.
  function refreshAncestorRepo(start) {
    var groupId = start.getAttribute("data-group");
    var seen = {};
    while (groupId && !seen[groupId]) {
      seen[groupId] = 1;
      var parentRowID = groupId.replace(/^tg-/, "");
      if (parentRowID.indexOf("repo:") === 0) {
        refreshRepoTbody(parentRowID);
        return;
      }
      var parent = document.getElementById("row-" + parentRowID);
      if (!parent) return;
      groupId = parent.getAttribute("data-group");
    }
  }

  function refreshRepoFromEvent(data) {
    var details = data && data.details;
    if (!details) return;
    if (typeof details === "string") {
      try { details = JSON.parse(details); } catch (e) { return; }
    }
    var reg = details.registry, repo = details.repository || details.repo;
    if (!reg || !repo) return;
    refreshRepoTbody("repo:" + reg + "|" + repo);
  }

  function liveTail(data) {
    var slot = document.getElementById("event-tail");
    if (!slot || !data) return;
    slot.innerHTML = "<code>" + (data.event_type || "?") + "</code> " +
                     (data.image_id ? "image #" + data.image_id : "");
  }

  function startSSE() {
    var url = base() + "/events";
    var src = new EventSource(url);
    src.addEventListener("event", function (ev) {
      var data = null;
      try { data = JSON.parse(ev.data); } catch (e) { /* ignore */ }
      if (!data) return;
      if (data.image_id && rowRefreshEvents[data.event_type] && !isLocalEcho(data.image_id)) {
        var row = document.getElementById("image-" + data.image_id);
        if (row) refreshAncestorRepo(row);
        refreshRow(data.image_id);
        refreshDetail(data.image_id);
      }
      if (repoRefreshEvents[data.event_type]) {
        refreshRepoFromEvent(data);
      }
      liveTail(data);
    });
    src.onerror = function () { /* let the browser auto-reconnect */ };
  }

  // ── Tree expand/collapse ──────────────────────────────────────────────
  var treeKey = function (id) { return "hermes:tree:" + id; };

  function applyToggle(btn, expanded) {
    btn.setAttribute("aria-expanded", String(expanded));
    var label = btn.dataset.expandLabel || "expand";
    btn.textContent = expanded ? "collapse" : label;
    var target = btn.getAttribute("aria-controls") || "";
    target.split(" ").forEach(function (group) {
      $$('[data-group="' + group + '"]').forEach(function (row) {
        if (expanded) {
          row.removeAttribute("hidden");
        } else {
          row.setAttribute("hidden", "");
          $$("[data-row-id][aria-expanded='true']", row).forEach(function (inner) {
            applyToggle(inner, false);
            try { localStorage.setItem(treeKey(inner.dataset.rowId), "0"); } catch (_) {}
          });
        }
      });
    });
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-row-id][aria-controls]");
    if (!btn) return;
    e.preventDefault();
    var open = btn.getAttribute("aria-expanded") !== "true";
    applyToggle(btn, open);
    try { localStorage.setItem(treeKey(btn.dataset.rowId), open ? "1" : "0"); } catch (_) {}
  });

  function restoreTree() {
    $$("[data-row-id][aria-controls]").forEach(function (btn) {
      // Skip toggles that are already in their persisted state, e.g.
      // a swap that re-rendered the row while it was expanded.
      if (btn.getAttribute("aria-expanded") === "true") return;
      var v = null;
      try { v = localStorage.getItem(treeKey(btn.dataset.rowId)); } catch (_) {}
      if (v === "1") applyToggle(btn, true);
    });
  }

  // Re-apply persisted tree state after every htmx swap so a freshly
  // swapped tbody (e.g. after a fetch or scan completes) keeps its
  // expanded subtrees expanded.
  document.body.addEventListener("htmx:afterSwap", restoreTree);
  document.body.addEventListener("htmx:oobAfterSwap", restoreTree);

  // ── Clipboard ─────────────────────────────────────────────────────────
  // Any element with `data-clipboard="..."` writes its value to the
  // clipboard on click.  The button keeps a `.icon-copy` and
  // `.icon-check` inline SVG; toggling `.copied` flips which one is
  // visible (CSS handles the swap).
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-clipboard]");
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    var text = btn.getAttribute("data-clipboard") || "";
    var done = function () {
      btn.classList.add("copied");
      setTimeout(function () { btn.classList.remove("copied"); }, 1000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    } else {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute"; ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (_) {}
      document.body.removeChild(ta);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { startSSE(); restoreTree(); });
  } else {
    startSSE();
    restoreTree();
  }
})();
