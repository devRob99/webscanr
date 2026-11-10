// Applies the saved theme before the page paints. Kept separate so it can load synchronously.
(function () {
  "use strict";
  try {
    var saved = window.localStorage.getItem("webscan-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (err) {
    /* storage unavailable: follow the system setting */
  }
})();
