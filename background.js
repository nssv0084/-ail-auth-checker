messenger.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
  try {
    const full = await messenger.messages.getFull(message.id);
    const headers = full.headers;

    // ヘッダー名は大文字小文字を区別しないようにフォールバックを用意
    const authHeaderRaw = headers["authentication-results"] || headers["Authentication-Results"] || [];
    const authHeader = authHeaderRaw.join("\n");

    const fromHeaderRaw = headers["from"] || headers["From"] || [""];
    const fromHeader = fromHeaderRaw[0];

    const result = parseAuthResults(authHeader, fromHeader);

    // 画面へのインジェクション処理
    await messenger.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });
    await messenger.scripting.insertCSS({
      target: { tabId: tab.id },
      files: ["content.css"]
    });

    // SPF/DKIM/DMARCを先に表示（RDAPを待たない）
    await messenger.tabs.sendMessage(tab.id, {
      type: "SHOW_AUTH_RESULT",
      data: result
    });

    // RDAPを非同期で取得し、取得後にドメイン情報を更新
    checkRdap(result.fromDomain).then(rdap => {
      messenger.tabs.sendMessage(tab.id, {
        type: "UPDATE_RDAP",
        data: rdap
      }).catch(() => {});
    });

  } catch (error) {
    console.error("Mail Auth Checker Error:", error);
  }
});

// CORSに対応しているRDAPサーバーのみ登録する。
// rdap.jprs.jp は CORS 非対応のため fetch がブロックされる（NetworkError確認済み）。
// .jp ドメインは lookupUrl（WHO.IS）のリンク表示にフォールバックする。
const RDAP_SERVERS = {
  "com": "https://rdap.verisign.com/com/v1",
  "net": "https://rdap.verisign.com/net/v1",
  // "jp": "https://rdap.jprs.jp/v1",  // CORS非対応
};

async function checkRdap(domain) {
  if (!domain) return null;

  const lookupUrl = `https://who.is/whois/${encodeURIComponent(domain)}`;
  const tld = domain.split(".").pop().toLowerCase();
  const baseUrl = RDAP_SERVERS[tld];

  // CORS非対応のTLDは検索リンクのみ返却
  if (!baseUrl) {
    return { registered: null, lookupUrl };
  }

  // 24時間キャッシュの確認
  const cacheKey = `rdap_${domain}`;
  try {
    const cached = await messenger.storage.local.get(cacheKey);
    const oneDay = 24 * 60 * 60 * 1000;
    if (cached[cacheKey] && (Date.now() - cached[cacheKey].ts < oneDay)) {
      return cached[cacheKey].data;
    }
  } catch (e) {
    console.warn("Storage access failed, bypassing cache:", e);
  }

  // RDAPサーバーへのリクエスト
  try {
    const url = `${baseUrl}/domain/${encodeURIComponent(domain)}`;
    const res = await fetch(url, {
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

    // キャッシュの保存
    await messenger.storage.local.set({ [cacheKey]: { ts: Date.now(), data } }).catch(() => {});
    return data;
  } catch (e) {
    console.error(`RDAP lookup failed for ${domain}:`, e);
    return { registered: null, lookupUrl };
  }
}

function parseAuthResults(header, from) {
  const fromDomain = extractDomain(from);

  // 安全に結果を抽出する汎用ヘルパー
  const extractResult = (text, regex, defaultVal = "none") => {
    const match = text.match(regex);
    return match && match[1] ? match[1].toLowerCase() : defaultVal;
  };

  const spf = extractResult(header, /spf=(\w+)/i);
  const dmarc = extractResult(header, /dmarc=(\w+)/i);
  const dmarcPolicy = extractResult(header, /dmarc=\w+\s*\([^)]*p=(\w+)/i, null);

  // DKIM署名のパース（複数署名に対応）
  const dkimMatches = [...header.matchAll(/dkim=(\w+)\s+header\.i=@([\w.-]+)/gi)];
  const dkimResults = dkimMatches.map(m => {
    const result = m[1].toLowerCase();
    const domain = m[2].toLowerCase();
    return {
      result,
      domain,
      // 組織ドメイン（コンダクトアライメント）まで考慮する場合は改良の余地あり
      aligned: domain === fromDomain.toLowerCase()
    };
  });

  return { fromDomain, spf, dmarc, dmarcPolicy, dkimResults };
}

function extractDomain(fromHeader) {
  if (!fromHeader) return "";
  // <user@example.com> もしくは user@example.com からドメインを抽出
  const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/(\S+@\S+)/);
  if (!emailMatch) return "";
  const email = emailMatch[1];
  return email.split("@").pop().trim();
}