// Kavlotryx console: theme toggle, bar widths, copy buttons. No framework.
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "kavlo-theme";

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function store(v) {
    try { localStorage.setItem(KEY, v); } catch (e) { /* private mode: keep it for this page */ }
  }
  var t = stored();
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t);

  function effective() {
    var a = root.getAttribute("data-theme");
    if (a === "light" || a === "dark") return a;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", function () {
        var next = effective() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        store(next);
      });
    });

    // Bar widths come from data-w so the CSP can forbid inline styles.
    document.querySelectorAll("[data-w]").forEach(function (el) {
      var w = Math.max(0, Math.min(100, parseFloat(el.getAttribute("data-w")) || 0));
      el.style.width = (w > 0 && w < 2 ? 2 : w) + "%";
    });

    document.querySelectorAll("[data-copy], [data-copy-text]").forEach(function (b) {
      b.addEventListener("click", function () {
        var text = b.getAttribute("data-copy-text");
        if (text === null) {
          var src = document.querySelector(b.getAttribute("data-copy"));
          text = src ? src.innerText : "";
        }
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          var old = b.lastChild.textContent;
          b.lastChild.textContent = "Copied";
          setTimeout(function () { b.lastChild.textContent = old; }, 1200);
        });
      });
    });
  });
})();
