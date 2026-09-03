// ENCLAVE client script.
//
// Three small conveniences, none of which the pages depend on: filter forms
// that submit as you type, tables that can be narrowed without a round trip,
// and confirmation on the handful of destructive buttons.

(function () {
  "use strict";

  // Submit a filter form shortly after typing stops, so the results follow the
  // query without a button press.
  document.querySelectorAll("form[data-autosubmit]").forEach(function (form) {
    var timer = null;
    form.addEventListener("input", function (ev) {
      if (ev.target.type === "submit") return;
      clearTimeout(timer);
      var delay = ev.target.tagName === "SELECT" ? 0 : 350;
      timer = setTimeout(function () { form.requestSubmit(); }, delay);
    });
  });

  // Narrow a table in the page. The input names the table by id.
  document.querySelectorAll("input[data-filters]").forEach(function (input) {
    var table = document.getElementById(input.getAttribute("data-filters"));
    if (!table) return;
    var counter = document.querySelector('[data-count-for="' + input.getAttribute("data-filters") + '"]');
    input.addEventListener("input", function () {
      var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
      var shown = 0;
      table.querySelectorAll("tbody tr").forEach(function (row) {
        var hay = row.textContent.toLowerCase();
        var hit = terms.every(function (t) { return hay.indexOf(t) !== -1; });
        row.hidden = !hit;
        if (hit) shown++;
      });
      if (counter) counter.textContent = shown;
    });
  });

  // A destructive button says what it is about to destroy.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.getAttribute("data-confirm"))) ev.preventDefault();
    });
  });

  // Sort a table by clicking a column header marked sortable.
  document.querySelectorAll("table[data-sortable] th[data-sort]").forEach(function (th) {
    th.style.cursor = "pointer";
    th.title = "Sort by " + th.textContent.trim();
    th.addEventListener("click", function () {
      var table = th.closest("table");
      var body = table.tBodies[0];
      var index = Array.prototype.indexOf.call(th.parentNode.children, th);
      var numeric = th.getAttribute("data-sort") === "number";
      var descending = th.getAttribute("data-dir") !== "desc";
      th.setAttribute("data-dir", descending ? "desc" : "asc");
      var rows = Array.prototype.slice.call(body.rows);
      rows.sort(function (a, b) {
        var x = a.cells[index] ? a.cells[index].textContent.trim() : "";
        var y = b.cells[index] ? b.cells[index].textContent.trim() : "";
        var cmp;
        if (numeric) {
          cmp = (parseFloat(x.replace(/[^0-9.\-]/g, "")) || 0) - (parseFloat(y.replace(/[^0-9.\-]/g, "")) || 0);
        } else {
          cmp = x.localeCompare(y, undefined, { numeric: true });
        }
        return descending ? -cmp : cmp;
      });
      rows.forEach(function (r) { body.appendChild(r); });
    });
  });
})();

// The column mapping screen.
//
// Twenty-seven dropdowns tell somebody nothing about what their file will
// become. This reads the sample rows already in the page, applies whatever
// mapping is currently chosen, and shows the first row interpreted as a
// finding. It updates as the selects change, so the screen answers the question
// it is really asking: did I get this right?
(function () {
  "use strict";

  var preview = document.querySelector('[data-role="preview"]');
  var sample = document.getElementById("sample-rows");
  if (!preview || !sample) return;

  var body = preview.querySelector('[data-role="preview-body"]');
  var status = document.querySelector('[data-role="status"]');
  var unmapped = document.querySelector('[data-role="unmapped"]');
  var selects = Array.prototype.slice.call(document.querySelectorAll("select[data-map-field]"));

  var headers = Array.prototype.map.call(sample.tHead.rows[0].cells, function (c) {
    return c.textContent.trim();
  });
  var firstRow = sample.tBodies[0] && sample.tBodies[0].rows[0];
  if (!firstRow) return;
  var values = Array.prototype.map.call(firstRow.cells, function (c) {
    return c.textContent.trim();
  });

  function valueFor(field) {
    var sel = document.querySelector('select[data-map-field="' + field + '"]');
    if (!sel || !sel.value) return "";
    var i = headers.indexOf(sel.value);
    return i >= 0 && i < values.length ? values[i] : "";
  }

  function line(label, value, muted) {
    var row = document.createElement("div");
    row.style.marginBottom = ".55rem";
    var k = document.createElement("div");
    k.className = "k";
    k.style.cssText = "font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-3);font-weight:600";
    k.textContent = label;
    var v = document.createElement("div");
    v.style.cssText = muted ? "color:var(--text-3)" : "";
    v.textContent = value;
    row.appendChild(k);
    row.appendChild(v);
    return row;
  }

  function severityFrom(raw, cvss) {
    var v = String(raw || "").trim().toLowerCase().replace(/^cat /, "");
    var map = {
      critical: "Critical", crit: "Critical", "4": "Critical", iv: "Critical",
      high: "High", "3": "High", i: "High",
      medium: "Medium", moderate: "Medium", med: "Medium", "2": "Medium", ii: "Medium",
      low: "Low", "1": "Low", iii: "Low"
    };
    if (map[v]) return map[v];
    var score = parseFloat(cvss);
    if (!isNaN(score) && score > 0) {
      if (score >= 9) return "Critical";
      if (score >= 7) return "High";
      if (score >= 4) return "Medium";
      return "Low";
    }
    return raw ? raw : "Informational";
  }

  function render() {
    var host = valueFor("asset_name") || valueFor("fqdn") || valueFor("ip");
    var title = valueFor("title");
    var cve = valueFor("cve");
    var cvss = valueFor("cvss");
    var severity = valueFor("severity");
    var status_ = valueFor("status");
    var fix = valueFor("fix");

    // A CVE is a complete finding on its own, which is why the title may be
    // left unmapped for a plain CVE list.
    var effectiveTitle = title || cve;

    body.textContent = "";
    if (!effectiveTitle) {
      var warn = document.createElement("p");
      warn.style.cssText = "margin:0;color:var(--text-2)";
      warn.textContent =
        "Nothing is chosen yet for the finding title or the CVE, so ENCLAVE cannot tell what " +
        "each row is reporting. Pick one of those two and this will fill in.";
      body.appendChild(warn);
    } else {
      body.appendChild(line("Host", host || "unnamed, which the import will flag", !host));
      body.appendChild(line("Finding", effectiveTitle));
      if (cve) body.appendChild(line("CVE", cve));
      body.appendChild(line("Severity", severityFrom(severity, cvss)));
      body.appendChild(line("Result", status_ || "Open, because no status column is chosen", !status_));
      if (fix) body.appendChild(line("Fix", fix.length > 120 ? fix.slice(0, 120) + "…" : fix));

      var note = document.createElement("p");
      note.style.cssText = "margin:.75rem 0 0;color:var(--text-3);font-size:.8rem";
      note.textContent = "The other rows are read the same way.";
      body.appendChild(note);
    }

    if (status) {
      status.className = effectiveTitle ? "notice ok" : "notice warn";
      status.textContent = effectiveTitle
        ? "Ready to import. Check the panel on the right, then press the button at the bottom."
        : "Choose which of your columns holds the finding title or the CVE. One of the two is required.";
    }

    if (unmapped) {
      var used = {};
      selects.forEach(function (s) { if (s.value) used[s.value] = true; });
      unmapped.textContent = "";
      var any = false;
      headers.forEach(function (h) {
        if (used[h]) return;
        any = true;
        var tag = document.createElement("span");
        tag.className = "tag";
        tag.textContent = h;
        unmapped.appendChild(tag);
      });
      if (!any) {
        var all = document.createElement("span");
        all.style.color = "var(--text-3)";
        all.textContent = "None. Every column in your file is being used.";
        unmapped.appendChild(all);
      }
    }
  }

  selects.forEach(function (s) { s.addEventListener("change", render); });
  render();
})();
