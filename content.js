browser.runtime.onMessage.addListener((msg) => {
  if (msg.type === "UPDATE_RDAP") {
    updateRdap(msg.data);
    return;
  }
  if (msg.type !== "SHOW_AUTH_RESULT") return;
  const data = msg.data;

  const existing = document.getElementById("mail-auth-banner");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "mail-auth-banner";

  const badges = [];

  // SPF
  if (data.spfDomain) {
    const alignType = data.spfAligned ? "aligned" : "infra";
    badges.push(makeBadge(`SPF (${data.spfDomain})`, data.spf, alignType));
  } else {
    badges.push(makeBadge("SPF", data.spf));
  }

  // DKIM: From と一致するものを優先表示
  const alignedDkim = data.dkimResults.find(d => d.aligned);
  const otherDkim = data.dkimResults.filter(d => !d.aligned);

  if (alignedDkim) {
    badges.push(makeBadge(`DKIM (${alignedDkim.domain})`, alignedDkim.result, "aligned"));
  }
  for (const d of otherDkim) {
    badges.push(makeBadge(`DKIM (${d.domain})`, d.result, "infra"));
  }

  // DMARC
  const dmarcBadge = makeBadge("DMARC", data.dmarc);
  if (data.dmarcPolicy) {
    dmarcBadge.title = browser.i18n.getMessage("dmarcPolicyPrefix") + data.dmarcPolicy;
  }
  badges.push(dmarcBadge);

  // From ドメイン注釈
  const note = document.createElement("span");
  note.className = "auth-note";
  note.textContent = browser.i18n.getMessage("fromDomainPrefix") + data.fromDomain;
  badges.push(note);

  // RDAP スロット（UPDATE_RDAP が届いたときのみ表示）
  const rdapSlot = document.createElement("span");
  rdapSlot.id = "mail-auth-rdap-slot";
  rdapSlot.style.display = "none";
  badges.push(rdapSlot);

  for (const b of badges) banner.appendChild(b);

  const msgBody = document.querySelector("body");
  if (msgBody) msgBody.prepend(banner);
});

function updateRdap(rdap) {
  const slot = document.getElementById("mail-auth-rdap-slot");
  if (!slot) return;
  slot.style.display = "";

  if (rdap && rdap.registered) {
    const regDate = new Date(rdap.registered);
    const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
    const level = ageDays < 30 ? "fail" : ageDays < 180 ? "warn" : "pass";
    slot.className = `auth-badge auth-${level}`;
    const locale = browser.i18n.getUILanguage();
    slot.textContent = browser.i18n.getMessage("rdapRegisteredPrefix") + regDate.toLocaleDateString(locale) + " (" + ageDays + browser.i18n.getMessage("daysAgo") + ")";
    slot.title = rdap.expires ? browser.i18n.getMessage("rdapExpiresPrefix") + new Date(rdap.expires).toLocaleDateString(locale) : "";
  } else if (rdap && rdap.lookupUrl) {
    const link = document.createElement("a");
    link.href = rdap.lookupUrl;
    link.target = "_blank";
    link.textContent = browser.i18n.getMessage("whoisSearch");
    link.className = "auth-link";
    slot.replaceWith(link);
  } else {
    slot.remove();
  }
}

function makeBadge(label, result, type = "") {
  const span = document.createElement("span");
  span.className = `auth-badge auth-${result} ${type ? "auth-" + type : ""}`.trim();

  const icon = result === "pass" ? "✓" : result === "fail" ? "✗" : "?";
  span.textContent = `${icon} ${label}`;
  return span;
}
