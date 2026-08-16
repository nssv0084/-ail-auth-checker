document.querySelectorAll("[data-i18n]").forEach(el => {
  const msg = browser.i18n.getMessage(el.dataset.i18n);
  if (msg) el.textContent = msg;
});

const checkbox = document.getElementById("rdapEnabled");
const status = document.getElementById("status");

messenger.storage.local.get("rdapEnabled").then(result => {
  checkbox.checked = !!result.rdapEnabled;
});

checkbox.addEventListener("change", () => {
  messenger.storage.local.set({ rdapEnabled: checkbox.checked }).then(() => {
    status.textContent = browser.i18n.getMessage("optionsSaved");
    setTimeout(() => { status.textContent = ""; }, 2000);
  });
});
