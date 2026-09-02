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
