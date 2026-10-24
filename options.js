document.querySelectorAll("[data-i18n]").forEach(el => {
  const msg = browser.i18n.getMessage(el.dataset.i18n);
  if (msg) el.textContent = msg;
});

const checkbox = document.getElementById("rdapEnabled");
const status = document.getElementById("status");

messenger.storage.local.get("rdapEnabled").then(result => {
  checkbox.checked = !!result.rdapEnabled;
});

function showSaved() {
  status.textContent = browser.i18n.getMessage("optionsSaved");
  setTimeout(() => { status.textContent = ""; }, 2000);
}

checkbox.addEventListener("change", () => {
  messenger.storage.local.set({ rdapEnabled: checkbox.checked }).then(showSaved);
});

const trustedInput = document.getElementById("trustedAuthservIds");

messenger.storage.local.get("trustedAuthservIds").then(result => {
  trustedInput.value = result.trustedAuthservIds || "";
});

trustedInput.addEventListener("change", () => {
  messenger.storage.local.set({ trustedAuthservIds: trustedInput.value.trim() }).then(showSaved);
});
