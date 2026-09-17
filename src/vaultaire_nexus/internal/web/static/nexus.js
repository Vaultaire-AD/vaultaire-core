// Vaultaire Nexus — petites commodités de l'interface. Tout fonctionne sans.
(function () {
  "use strict";

  function copy(text, anchor) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () {
      var tip = document.createElement("span");
      tip.className = "copy-flash";
      tip.textContent = "copié";
      var host = anchor.closest("pre") || anchor.parentElement;
      host.style.position = host.style.position || "relative";
      host.appendChild(tip);
      setTimeout(function () { tip.remove(); }, 1200);
    });
  }

  document.addEventListener("click", function (e) {
    var el = e.target.closest("[data-copy]");
    if (el) { copy(el.getAttribute("data-copy"), el); return; }
    var pre = e.target.closest("pre.copyable");
    if (pre && !window.getSelection().toString()) { copy(pre.innerText.trim(), pre); }
  });

  // Confirmation des suppressions.
  document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { e.preventDefault(); }
  });

  // Filtres qui s'appliquent au changement.
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // Champs propres à un type de dépôt.
  var type = document.getElementById("repo-type");
  function syncType() {
    document.querySelectorAll("[data-for-type]").forEach(function (el) {
      el.classList.toggle("show", el.getAttribute("data-for-type") === type.value);
    });
  }
  if (type) { type.addEventListener("change", syncType); syncType(); }
})();
