// 2段階TLD（例: co.jp, or.jp, ne.jp, ac.jp, go.jp, com.au 等）
const TWO_PART_TLDS = new Set([
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp", "lg.jp", "gr.jp",
  "co.uk", "org.uk", "me.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "co.kr", "or.kr", "ne.kr",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn",
]);

function getOrgDomain(domain) {
  if (!domain) return "";
  const d = domain.toLowerCase();
  const parts = d.split(".");
  if (parts.length < 2) return d;

  const twoPartCandidate = parts.slice(-2).join(".");
  if (TWO_PART_TLDS.has(twoPartCandidate) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// RFC 8601 のヘッダーを字句に分解する。コメント・引用符内の ";" "=" は区切りとして扱わない。
function lexAuthResults(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === ";" || c === "=") { out.push({ t: c }); i++; continue; }
    if (c === "(") {
      let depth = 0, text = "";
      for (; i < s.length; i++) {
        const ch = s[i];
        if (ch === "\\") { text += s[i + 1] || ""; i++; continue; }
        if (ch === "(") { if (depth++ > 0) text += ch; continue; }
        if (ch === ")") { if (--depth === 0) { i++; break; } text += ch; continue; }
        text += ch;
      }
      out.push({ t: "comment", v: text });
      continue;
    }
    // 隣接する引用符部分と非引用部分は 1 つの値として連結する（例: "a b"@example.com）
    let text = "";
    while (i < s.length && !/[\s;=()]/.test(s[i])) {
      if (s[i] === '"') {
        for (i++; i < s.length; i++) {
          const ch = s[i];
          if (ch === "\\") { text += s[i + 1] || ""; i++; continue; }
          if (ch === '"') { i++; break; }
          text += ch;
        }
      } else {
        text += s[i++];
      }
    }
    out.push({ t: "value", v: text });
  }
  return out;
}

// ヘッダーを { authservId, resinfos: [{ method, result, props, comments }] } に分解する。
// 各 resinfo は先頭の method=result と、その後ろの ptype.property=value のみを読む。
function parseAuthHeader(header) {
  const segments = [[]];
  for (const tok of lexAuthResults(header || "")) {
    if (tok.t === ";") segments.push([]);
    else segments[segments.length - 1].push(tok);
  }

  let authservId = "";
  const first = segments[0].filter(t => t.t !== "comment");
  // authserv-id を省略した断片（"spf=pass ..." のみ）も受け付ける
  if (first.length && !(first[1] && first[1].t === "=")) {
    authservId = first[0].t === "value" ? first[0].v.toLowerCase() : "";
    segments.shift();
  }

  const resinfos = [];
  for (const seg of segments) {
    const vals = seg.filter(t => t.t !== "comment");
    if (vals.length < 3 || vals[0].t !== "value" || vals[1].t !== "=" || vals[2].t !== "value") continue;
    const method = vals[0].v.split("/")[0].toLowerCase();
    const result = vals[2].v.toLowerCase();
    if (!/^\w+$/.test(method) || !/^\w+$/.test(result)) continue;

    const props = {};
    for (let k = 3; k + 2 < vals.length; ) {
      if (vals[k].t === "value" && vals[k + 1].t === "=" && vals[k + 2].t === "value") {
        const key = vals[k].v.toLowerCase();
        if (!(key in props)) props[key] = vals[k + 2].v;
        k += 3;
      } else {
        k++;
      }
    }
    const comments = seg.filter(t => t.t === "comment").map(t => t.v);
    resinfos.push({ method, result, props, comments });
  }
  return { authservId, resinfos };
}

function getAuthservId(header) {
  return parseAuthHeader(header).authservId;
}

const DOMAIN_RE = /^[a-z0-9.-]+$/;

function domainOf(value) {
  if (!value) return null;
  const d = value.split("@").pop().trim().toLowerCase();
  return DOMAIN_RE.test(d) ? d : null;
}

function parseTrustedIds(text) {
  if (!text) return [];
  return text.split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
}

// 送信者は任意の Authentication-Results を本文作成時に埋め込めるため、信頼できるものだけを選ぶ。
// headers は上から（受信側 MTA が最後に付けたものが先頭）の順。
//   trustedIds あり: 最上位のヘッダーの authserv-id が一致するときのみ採用（verified）。それ以外は untrusted。
//     受信サーバーが付与しなかったメールでは、下位にある送信者の偽造ヘッダーが最上位になり得るため、下位は探さない。
//   trustedIds なし: 最上位の 1 本のみ採用（unverified）。
function selectAuthResults(headers, trustedIds) {
  const list = (headers || []).filter(h => h && h.trim());
  const top = list[0] || "";
  const authservId = getAuthservId(top);
  if (trustedIds && trustedIds.length > 0) {
    const ids = new Set(trustedIds.map(s => s.toLowerCase()));
    if (!top || !ids.has(authservId)) return { header: "", trust: "untrusted", authservId };
    return { header: top, trust: "verified", authservId };
  }
  return { header: top, trust: "unverified", authservId };
}

function parseAuthResults(header, from) {
  const fromDomain = extractDomain(from);
  const fromOrg = getOrgDomain(fromDomain);
  const { resinfos } = parseAuthHeader(header);

  const spfInfo = resinfos.find(r => r.method === "spf");
  const spf = spfInfo ? spfInfo.result : "none";
  const spfDomain = spfInfo ? domainOf(spfInfo.props["smtp.mailfrom"] || spfInfo.props["smtp.helo"]) : null;
  const spfAligned = !!spfDomain && getOrgDomain(spfDomain) === fromOrg;

  const dmarcInfo = resinfos.find(r => r.method === "dmarc");
  const dmarc = dmarcInfo ? dmarcInfo.result : "none";
  let dmarcPolicy = null;
  if (dmarcInfo) {
    for (const c of dmarcInfo.comments) {
      const m = c.match(/(?:^|\s)p=(\w+)/i);
      if (m) { dmarcPolicy = m[1].toLowerCase(); break; }
    }
  }

  const dkimResults = [];
  for (const r of resinfos) {
    if (r.method !== "dkim") continue;
    const i = r.props["header.i"];
    if (!i || !i.includes("@")) continue;
    const domain = domainOf(i);
    if (!domain) continue;
    dkimResults.push({ result: r.result, domain, aligned: getOrgDomain(domain) === fromOrg });
  }

  return { fromDomain, spf, spfDomain, spfAligned, dmarc, dmarcPolicy, dkimResults };
}

function extractDomain(fromHeader) {
  if (!fromHeader) return "";
  const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/(\S+@\S+)/);
  if (!emailMatch) return "";
  const email = emailMatch[1];
  return email.split("@").pop().trim();
}

if (typeof module !== "undefined") module.exports = { parseAuthResults, extractDomain, getOrgDomain, getAuthservId, parseTrustedIds, selectAuthResults };
