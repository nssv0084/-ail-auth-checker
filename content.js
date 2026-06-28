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
  badges.push(makeBadge("SPF", data.spf));

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
    dmarcBadge.title = `ポリシー: p=${data.dmarcPolicy}`;
  }
  badges.push(dmarcBadge);

  // From ドメイン注釈
  const note = document.createElement("span");
  note.className = "auth-note";
  note.textContent = `送信元: ${data.fromDomain}`;
  badges.push(note);

  // RDAP ドメイン取得日（後から UPDATE_RDAP で差し替えるプレースホルダー）
  const rdapSlot = document.createElement("span");
  rdapSlot.id = "mail-auth-rdap-slot";
  rdapSlot.className = "auth-badge auth-none";
  rdapSlot.textContent = "取得日: 確認中…";
  badges.push(rdapSlot);

  for (const b of badges) banner.appendChild(b);

  const msgBody = document.querySelector("body");
  if (msgBody) msgBody.prepend(banner);
});

function updateRdap(rdap) {
  const slot = document.getElementById("mail-auth-rdap-slot");
  if (!slot) return;

  if (rdap && rdap.registered) {
    const regDate = new Date(rdap.registered);
    const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
    const level = ageDays < 30 ? "fail" : ageDays < 180 ? "warn" : "pass";
    slot.className = `auth-badge auth-${level}`;
    slot.textContent = `取得: ${regDate.toLocaleDateString("ja-JP")} (${ageDays}日前)`;
    slot.title = rdap.expires ? `有効期限: ${new Date(rdap.expires).toLocaleDateString("ja-JP")}` : "";
  } else if (rdap && rdap.lookupUrl) {
    const link = document.createElement("a");
    link.href = rdap.lookupUrl;
    link.target = "_blank";
    link.textContent = "? WHOIS検索";
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
