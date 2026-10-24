const assert = require("assert");
const { parseAuthResults, extractDomain, getOrgDomain, getAuthservId, parseTrustedIds, selectAuthResults } = require("../parser.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${e.message}`);
    failed++;
  }
}

// ─── getOrgDomain ─────────────────────────────────────────────────

console.log("\ngetOrgDomain");

test("通常ドメイン", () => {
  assert.strictEqual(getOrgDomain("example.com"), "example.com");
});

test("サブドメイン (.com)", () => {
  assert.strictEqual(getOrgDomain("mail.example.com"), "example.com");
});

test("2段階TLD (.co.jp)", () => {
  assert.strictEqual(getOrgDomain("uccard.co.jp"), "uccard.co.jp");
});

test("サブドメイン + 2段階TLD (.co.jp)", () => {
  assert.strictEqual(getOrgDomain("em3513.mail.uccard.co.jp"), "uccard.co.jp");
});

test("mail.uccard.co.jp", () => {
  assert.strictEqual(getOrgDomain("mail.uccard.co.jp"), "uccard.co.jp");
});

test("amazon.co.jp", () => {
  assert.strictEqual(getOrgDomain("amazon.co.jp"), "amazon.co.jp");
});

// ─── extractDomain ────────────────────────────────────────────────

console.log("\nextractDomain");

test("angle bracket形式", () => {
  assert.strictEqual(extractDomain("Amazon <no-reply@amazon.co.jp>"), "amazon.co.jp");
});

test("メールアドレスのみ", () => {
  assert.strictEqual(extractDomain("no-reply@amazon.co.jp"), "amazon.co.jp");
});

test("空文字", () => {
  assert.strictEqual(extractDomain(""), "");
});

test("null/undefined", () => {
  assert.strictEqual(extractDomain(null), "");
});

// ─── SPF ─────────────────────────────────────────────────────────

console.log("\nSPF");

test("SPF pass", () => {
  const r = parseAuthResults("spf=pass smtp.mailfrom=amazon.co.jp", "no-reply@amazon.co.jp");
  assert.strictEqual(r.spf, "pass");
});

test("SPF アラインメント一致（完全一致）", () => {
  const r = parseAuthResults("spf=pass smtp.mailfrom=amazon.co.jp", "no-reply@amazon.co.jp");
  assert.strictEqual(r.spfDomain, "amazon.co.jp");
  assert.strictEqual(r.spfAligned, true);
});

test("SPF アラインメント一致（組織ドメイン一致、.co.jp）", () => {
  // UCカードの実例: em3513.mail.uccard.co.jp vs mail.uccard.co.jp
  const header = 'spf=pass smtp.mailfrom="bounces@em3513.mail.uccard.co.jp"';
  const r = parseAuthResults(header, "info@mail.uccard.co.jp");
  assert.strictEqual(r.spfDomain, "em3513.mail.uccard.co.jp");
  assert.strictEqual(r.spfAligned, true);
});

test("SPF アラインメント不一致（別組織）", () => {
  const r = parseAuthResults("spf=pass smtp.mailfrom=mail.amazonses.com", "no-reply@amazon.co.jp");
  assert.strictEqual(r.spfDomain, "mail.amazonses.com");
  assert.strictEqual(r.spfAligned, false);
});

test("SPF smtp.mailfrom にユーザー部あり（クォートなし）", () => {
  const r = parseAuthResults("spf=pass smtp.mailfrom=bounce@mail.example.com", "user@example.com");
  assert.strictEqual(r.spfDomain, "mail.example.com");
  assert.strictEqual(r.spfAligned, true);
});

test("SPF smtp.mailfrom にユーザー部あり（クォートあり）", () => {
  // 実際のGmailヘッダーはクォート付き
  const r = parseAuthResults('spf=pass smtp.mailfrom="bounce+123@em3513.mail.uccard.co.jp"', "info@mail.uccard.co.jp");
  assert.strictEqual(r.spfDomain, "em3513.mail.uccard.co.jp");
  assert.strictEqual(r.spfAligned, true);
});

test("SPF smtp.mailfrom なし（古いヘッダー）", () => {
  const r = parseAuthResults("spf=pass", "no-reply@amazon.co.jp");
  assert.strictEqual(r.spf, "pass");
  assert.strictEqual(r.spfDomain, null);
  assert.strictEqual(r.spfAligned, false);
});

test("SPF fail", () => {
  const r = parseAuthResults("spf=fail smtp.mailfrom=evil.com", "admin@bank.co.jp");
  assert.strictEqual(r.spf, "fail");
  assert.strictEqual(r.spfAligned, false);
});

// ─── DKIM ────────────────────────────────────────────────────────

console.log("\nDKIM");

test("DKIM pass アラインメント一致（完全一致）", () => {
  const r = parseAuthResults("dkim=pass header.i=@amazon.co.jp", "no-reply@amazon.co.jp");
  assert.strictEqual(r.dkimResults[0].aligned, true);
});

test("DKIM アラインメント一致（組織ドメイン一致、.co.jp）", () => {
  // UCカードの実例: mail.uccard.co.jp vs From: mail.uccard.co.jp → 完全一致
  const r = parseAuthResults("dkim=pass header.i=@mail.uccard.co.jp", "info@mail.uccard.co.jp");
  assert.strictEqual(r.dkimResults[0].aligned, true);
});

test("DKIM アラインメント不一致（別組織: amazonses.com）", () => {
  const r = parseAuthResults("dkim=pass header.i=@amazonses.com", "no-reply@amazon.co.jp");
  assert.strictEqual(r.dkimResults[0].aligned, false);
});

test("DKIM header.i にローカルパートあり（selector@domain形式）", () => {
  const r = parseAuthResults("dkim=pass header.i=s1._domainkey@example.com", "user@example.com");
  assert.strictEqual(r.dkimResults[0].domain, "example.com");
  assert.strictEqual(r.dkimResults[0].aligned, true);
});

test("DKIM 括弧付きコメント（1024-bit key; unprotected）", () => {
  const header = "dkim=pass (1024-bit key; unprotected) header.i=@amazon.co.jp";
  const r = parseAuthResults(header, "no-reply@amazon.co.jp");
  assert.strictEqual(r.dkimResults[0].domain, "amazon.co.jp");
});

test("DKIM 複数署名（uccard実例: mail.uccard.co.jp + sendgrid.info）", () => {
  const header = [
    "dkim=pass header.i=@mail.uccard.co.jp header.s=s1",
    "dkim=pass header.i=@sendgrid.info header.s=smtpapi"
  ].join("; ");
  const r = parseAuthResults(header, "info@mail.uccard.co.jp");
  assert.strictEqual(r.dkimResults.length, 2);
  assert.strictEqual(r.dkimResults.filter(d => d.aligned).length, 1);
  assert.strictEqual(r.dkimResults.filter(d => !d.aligned).length, 1);
});

test("DKIM ヘッダーが複数行（join後）", () => {
  const header = [
    "mx.example.com; spf=pass smtp.mailfrom=amazon.com",
    "mx.example.com; dkim=pass header.i=@amazon.com"
  ].join("\n");
  const r = parseAuthResults(header, "event@amazon.com");
  assert.strictEqual(r.spf, "pass");
  assert.strictEqual(r.dkimResults.length, 1);
  assert.strictEqual(r.dkimResults[0].aligned, true);
});

test("DKIM none", () => {
  const r = parseAuthResults("dkim=none", "user@example.com");
  assert.strictEqual(r.dkimResults.length, 0);
});

// ─── DMARC ───────────────────────────────────────────────────────

console.log("\nDMARC");

test("DMARC pass", () => {
  const r = parseAuthResults("dmarc=pass", "user@example.com");
  assert.strictEqual(r.dmarc, "pass");
  assert.strictEqual(r.dmarcPolicy, null);
});

test("DMARC fail with policy", () => {
  const r = parseAuthResults("dmarc=fail (p=reject) header.from=example.com", "user@example.com");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dmarcPolicy, "reject");
});

test("DMARC policy quarantine", () => {
  const r = parseAuthResults("dmarc=pass (p=quarantine) header.from=example.com", "user@example.com");
  assert.strictEqual(r.dmarcPolicy, "quarantine");
});

// ─── 信頼境界（authserv-id） ──────────────────────────────────────

console.log("\nTrust boundary");

const REAL = "mx.google.com; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail (p=reject) header.from=bank.co.jp";
const FORGED = "mx.google.com; spf=pass smtp.mailfrom=bank.co.jp; dkim=pass header.i=@bank.co.jp; dmarc=pass";
const FORGED_OTHER = "fake.example; spf=pass smtp.mailfrom=bank.co.jp; dkim=pass header.i=@bank.co.jp; dmarc=pass";

test("getAuthservId: 通常", () => {
  assert.strictEqual(getAuthservId("mx.google.com; spf=pass"), "mx.google.com");
});

test("getAuthservId: version 付き・コメント付き", () => {
  assert.strictEqual(getAuthservId(" (c) MX.Example.COM 1; spf=pass"), "mx.example.com");
});

test("parseTrustedIds: カンマ・空白区切り", () => {
  assert.deepStrictEqual(parseTrustedIds(" mx.google.com, MX2.example.com  a.b "), ["mx.google.com", "mx2.example.com", "a.b"]);
  assert.deepStrictEqual(parseTrustedIds(""), []);
  assert.deepStrictEqual(parseTrustedIds(undefined), []);
});

test("未設定: 最上位のみ採用し、下の偽造ヘッダーは無視", () => {
  const s = selectAuthResults([REAL, FORGED], []);
  assert.strictEqual(s.trust, "unverified");
  const r = parseAuthResults(s.header, "info@bank.co.jp");
  assert.strictEqual(r.spf, "fail");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dkimResults.length, 0);
});

test("未設定: 上位ヘッダーに無い項目を下の偽造ヘッダーで補わない", () => {
  const s = selectAuthResults(["mx.google.com; dkim=none", FORGED], []);
  const r = parseAuthResults(s.header, "info@bank.co.jp");
  assert.strictEqual(r.spf, "none");
  assert.strictEqual(r.dmarc, "none");
});

test("設定あり: 一致する authserv-id のみ採用", () => {
  const s = selectAuthResults([REAL, FORGED_OTHER], ["mx.google.com"]);
  assert.strictEqual(s.trust, "verified");
  const r = parseAuthResults(s.header, "info@bank.co.jp");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dkimResults.length, 0);
});

test("設定あり: 信頼済み authserv-id を騙った下位の偽造ヘッダーは無視", () => {
  const s = selectAuthResults([REAL, FORGED], ["mx.google.com"]);
  assert.strictEqual(s.trust, "verified");
  const r = parseAuthResults(s.header, "info@bank.co.jp");
  assert.strictEqual(r.spf, "fail");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dkimResults.length, 0);
});

test("設定あり: 一致なし（受信側が A-R を付けず偽造のみ）→ untrusted", () => {
  const s = selectAuthResults([FORGED_OTHER], ["mx.google.com"]);
  assert.strictEqual(s.trust, "untrusted");
  assert.strictEqual(s.header, "");
  assert.strictEqual(s.authservId, "fake.example");
  const r = parseAuthResults(s.header, "info@bank.co.jp");
  assert.strictEqual(r.dmarc, "none");
});

test("設定あり: 最上位が別サーバーなら、下位の信頼 ID 名乗りヘッダーは untrusted（ケース2）", () => {
  const s = selectAuthResults(["mx.other.example; spf=none", FORGED], ["mx.google.com"]);
  assert.strictEqual(s.trust, "untrusted");
  assert.strictEqual(s.header, "");
  assert.strictEqual(s.authservId, "mx.other.example");
});

test("設定あり: ヘッダーなし → untrusted", () => {
  assert.strictEqual(selectAuthResults([], ["mx.google.com"]).trust, "untrusted");
});

// ─── 項目単位のパース（ケース3: 値・コメントへの注入） ─────────────

console.log("\nResinfo parsing");

test("引用符付き smtp.mailfrom 内の dmarc=/dkim= を結果として読まない", () => {
  const h = 'mx.google.com; spf=fail smtp.mailfrom="x dmarc=pass dkim=pass header.i=@bank.co.jp"@evil.example; dmarc=fail (p=reject) header.from=bank.co.jp';
  const r = parseAuthResults(h, "info@bank.co.jp");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dmarcPolicy, "reject");
  assert.strictEqual(r.dkimResults.length, 0);
  assert.strictEqual(r.spfDomain, "evil.example");
  assert.strictEqual(r.spfAligned, false);
});

test("引用符付きローカルパートの @ をドメインとして読まない", () => {
  const h = 'mx.google.com; spf=pass smtp.mailfrom="x@bank.co.jp"@evil.example';
  const r = parseAuthResults(h, "info@bank.co.jp");
  assert.strictEqual(r.spfDomain, "evil.example");
  assert.strictEqual(r.spfAligned, false);
});

test("コメント内の dmarc=/dkim= を結果として読まない", () => {
  const h = "mx.google.com; spf=fail (sender said: dmarc=pass; dkim=pass header.i=@bank.co.jp) smtp.mailfrom=evil.example; dmarc=fail header.from=bank.co.jp";
  const r = parseAuthResults(h, "info@bank.co.jp");
  assert.strictEqual(r.dmarc, "fail");
  assert.strictEqual(r.dkimResults.length, 0);
});

test("コメント内の p= は DMARC 以外の項目から拾わない", () => {
  const h = "mx.google.com; spf=pass (p=reject) smtp.mailfrom=example.com; dmarc=pass header.from=example.com";
  const r = parseAuthResults(h, "user@example.com");
  assert.strictEqual(r.dmarcPolicy, null);
});

test("Gmail 実形式", () => {
  const h = [
    "mx.google.com;",
    "       dkim=pass header.i=@mail.uccard.co.jp header.s=s1 header.b=abc;",
    "       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=def;",
    '       spf=pass (google.com: domain of bounces+1@em3513.mail.uccard.co.jp designates 1.2.3.4 as permitted sender) smtp.mailfrom="bounces+1@em3513.mail.uccard.co.jp";',
    "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mail.uccard.co.jp"
  ].join("\r\n");
  const r = parseAuthResults(h, "info@mail.uccard.co.jp");
  assert.strictEqual(r.spf, "pass");
  assert.strictEqual(r.spfDomain, "em3513.mail.uccard.co.jp");
  assert.strictEqual(r.spfAligned, true);
  assert.strictEqual(r.dmarc, "pass");
  assert.strictEqual(r.dmarcPolicy, "none");
  assert.strictEqual(r.dkimResults.length, 2);
  assert.strictEqual(getAuthservId(h), "mx.google.com");
});

test("authserv-id のみ（none）", () => {
  const r = parseAuthResults("mx.google.com; none", "user@example.com");
  assert.strictEqual(r.spf, "none");
  assert.strictEqual(r.dmarc, "none");
  assert.strictEqual(r.dkimResults.length, 0);
});

test("設定あり: 大文字小文字を区別しない", () => {
  const s = selectAuthResults(["MX.Google.COM; dmarc=pass"], ["mx.google.com"]);
  assert.strictEqual(s.trust, "verified");
});

test("ヘッダーなし", () => {
  assert.deepStrictEqual(selectAuthResults([], []), { header: "", trust: "unverified", authservId: "" });
});

// ─── 結果 ─────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
