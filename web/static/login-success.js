(() => {
  const page = document.querySelector("[data-login-success]");
  if (!page) {
    return;
  }
  const returnTo = page.dataset.returnTo;
  if (!returnTo || !returnTo.startsWith("/") || returnTo.startsWith("//")) {
    return;
  }
  window.setTimeout(() => {
    window.location.replace(returnTo);
  }, 1600);
})();
