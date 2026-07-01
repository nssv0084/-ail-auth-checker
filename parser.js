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

function parseAuthResults(header, from) {
  const fromDomain = extractDomain(from);
  const fromOrg = getOrgDomain(fromDomain);

  const extractResult = (text, regex, defaultVal = "none") => {
    const match = text.match(regex);
    return match && match[1] ? match[1].toLowerCase() : defaultVal;
  };

  const spf = extractResult(header, /spf=(\w+)/i);

  // smtp.mailfrom / smtp.helo から SPFアラインメントを確認
  const mailfromMatch = header.match(/smtp\.mailfrom="?([^\s;"]+)"?/i) || header.match(/smtp\.helo=([^\s;]+)/i);
  let spfDomain = null;
  let spfAligned = false;
  if (mailfromMatch) {
    const mailfrom = mailfromMatch[1];
    spfDomain = (mailfrom.includes("@") ? mailfrom.split("@").pop() : mailfrom).trim().toLowerCase();
    spfAligned = getOrgDomain(spfDomain) === fromOrg;
  }

  const dmarc = extractResult(header, /dmarc=(\w+)/i);
  const dmarcPolicy = extractResult(header, /dmarc=\w+\s*\([^)]*p=(\w+)/i, null);

  // DKIM署名のパース（複数署名に対応）
  const dkimMatches = [...header.matchAll(/dkim=(\w+)(?:[^;(]|\([^)]*\))*?header\.i=[^@\s]*@([\w.-]+)/gi)];
  const dkimResults = dkimMatches.map(m => {
    const result = m[1].toLowerCase();
    const domain = m[2].toLowerCase();
    return {
      result,
      domain,
      aligned: getOrgDomain(domain) === fromOrg
    };
  });

  return { fromDomain, spf, spfDomain, spfAligned, dmarc, dmarcPolicy, dkimResults };
}

function extractDomain(fromHeader) {
  if (!fromHeader) return "";
  const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/(\S+@\S+)/);
  if (!emailMatch) return "";
  const email = emailMatch[1];
  return email.split("@").pop().trim();
}

if (typeof module !== "undefined") module.exports = { parseAuthResults, extractDomain, getOrgDomain };
