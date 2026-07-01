const assert = require("assert");
const { parseAuthResults, extractDomain, getOrgDomain } = require("../parser.js");

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

// ─── 結果 ─────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
