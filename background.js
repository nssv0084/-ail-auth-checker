messenger.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
  const full = await messenger.messages.getFull(message.id);
  const headers = full.headers;

  const authHeader = (headers["authentication-results"] || []).join("\n");
  const fromHeader = (headers["from"] || [""])[0];

  const result = parseAuthResults(authHeader, fromHeader);
  result.rdap = await checkRdap(result.fromDomain).catch(e => ({ error: String(e) }));

  await messenger.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["content.js"]
  });

  await messenger.scripting.insertCSS({
    target: { tabId: tab.id },
    files: ["content.css"]
  });

  await messenger.tabs.sendMessage(tab.id, {
    type: "SHOW_AUTH_RESULT",
    data: result
  });
});

// CORSに対応しているRDAPサーバーのみ
const RDAP_SERVERS = {
  "com": "https://rdap.verisign.com/com/v1",
  "net": "https://rdap.verisign.com/net/v1",
};

async function checkRdap(domain) {
  if (!domain) return null;

  const lookupUrl = `https://who.is/whois/${encodeURIComponent(domain)}`;
  const tld = domain.split(".").pop().toLowerCase();
  const base = RDAP_SERVERS[tld];

  // CORSが動かないTLDはWHOISリンクのみ返す
  if (!base) return { registered: null, lookupUrl };

  const cacheKey = `rdap_${domain}`;
  const cached = await messenger.storage.local.get(cacheKey);
  if (cached[cacheKey]) {
    const entry = cached[cacheKey];
    if (Date.now() - entry.ts < 24 * 60 * 60 * 1000) {
      return entry.data;
    }
  }

  try {
    const res = await fetch(`${base}/domain/${encodeURIComponent(domain)}`, {
      headers: { "Accept": "application/rdap+json" }
    });
    if (!res.ok) return { registered: null, lookupUrl };

    const json = await res.json();
    const events = json.events || [];
    const registration = events.find(e => e.eventAction === "registration");
    const expiration = events.find(e => e.eventAction === "expiration");

    const data = {
      registered: registration ? registration.eventDate : null,
      expires: expiration ? expiration.eventDate : null,
      lookupUrl,
    };

    await messenger.storage.local.set({ [cacheKey]: { ts: Date.now(), data } });
    return data;
  } catch (e) {
    return { registered: null, lookupUrl };
  }
}

function parseAuthResults(header, from) {
  const fromDomain = extractDomain(from);

  const spf = extractResult(header, /spf=(\w+)/i);
  const dmarc = extractResult(header, /dmarc=(\w+)/i);
  const dmarcPolicy = extractResult(header, /dmarc=\w+\s*\([^)]*p=(\w+)/i);

  const dkimMatches = [...header.matchAll(/dkim=(\w+)\s+header\.i=@([\w.-]+)/gi)];
  const dkimResults = dkimMatches.map(m => ({
    result: m[1].toLowerCase(),
    domain: m[2].toLowerCase(),
    aligned: m[2].toLowerCase() === fromDomain.toLowerCase()
  }));

  return { fromDomain, spf, dmarc, dmarcPolicy, dkimResults };
}

function extractDomain(from) {
  const match = from.match(/@([\w.-]+)/);
  return match ? match[1] : "";
}

function extractResult(header, pattern) {
  const match = header.match(pattern);
  return match ? match[1].toLowerCase() : "none";
}
