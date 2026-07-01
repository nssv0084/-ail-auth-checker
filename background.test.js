const { parseAuthResults, extractDomain } = require("./background");

// --- extractDomain ---

describe("extractDomain", () => {
  test("アングルブラケット形式 <user@example.com>", () => {
    expect(extractDomain("John Doe <john@example.com>")).toBe("example.com");
  });

  test("ブラケットなし user@example.com", () => {
    expect(extractDomain("john@example.com")).toBe("example.com");
  });

  test("サブドメイン付き", () => {
    expect(extractDomain("<user@mail.amazon.com>")).toBe("mail.amazon.com");
  });

  test("空文字列は空文字を返す", () => {
    expect(extractDomain("")).toBe("");
  });

  test("null/undefined は空文字を返す", () => {
    expect(extractDomain(null)).toBe("");
    expect(extractDomain(undefined)).toBe("");
  });

  test("メールアドレスを含まない文字列は空文字を返す", () => {
    expect(extractDomain("名前だけ")).toBe("");
  });

  // mail_auth_002 で扱った AWS SES 送信者のケース
  test("AWSのSESから送られた場合: <ksakatsu@amazon.com>", () => {
    expect(extractDomain("Koichi Sakatsuji <ksakatsu@amazon.com>")).toBe("amazon.com");
  });
});

// --- parseAuthResults ---

describe("parseAuthResults", () => {
  // mail_auth_001 で言及した「三冠PASS」ケース
  test("SPF/DKIM/DMARC すべてPASS（三冠）", () => {
    const header = `spf=pass smtp.mailfrom=ikehiroki.com;
      dkim=pass header.i=@ikehiroki.com;
      dmarc=pass (p=none) header.from=ikehiroki.com`;
    const from = "hiroki@ikehiroki.com";

    const result = parseAuthResults(header, from);

    expect(result.spf).toBe("pass");
    expect(result.dmarc).toBe("pass");
    expect(result.dmarcPolicy).toBe("none");
    expect(result.dkimResults).toHaveLength(1);
    expect(result.dkimResults[0].result).toBe("pass");
    expect(result.dkimResults[0].aligned).toBe(true);
  });

  // mail_auth_001 で言及したフィッシングメール相当：PASSするが from ドメインが怪しい
  test("認証はPASSするが fromDomain は不審なドメイン", () => {
    const header = `spf=pass; dkim=pass header.i=@jgmiwymm.0kfbv20.shop; dmarc=pass`;
    const from = "info@jgmiwymm.0kfbv20.shop";

    const result = parseAuthResults(header, from);

    expect(result.spf).toBe("pass");
    expect(result.dmarc).toBe("pass");
    expect(result.fromDomain).toBe("jgmiwymm.0kfbv20.shop");
    expect(result.dkimResults[0].aligned).toBe(true);
  });

  // mail_auth_002 で扱った AWS NTT Day メールのケース: 複数 DKIM 署名
  test("DKIM 複数署名: amazon.com と amazonses.com", () => {
    const header = `spf=pass smtp.mailfrom=amazonses.com;
      dkim=pass header.i=@amazon.com;
      dkim=pass header.i=@amazonses.com;
      dmarc=pass`;
    const from = "Koichi Sakatsuji <ksakatsu@amazon.com>";

    const result = parseAuthResults(header, from);

    expect(result.fromDomain).toBe("amazon.com");
    expect(result.dkimResults).toHaveLength(2);

    const aligned = result.dkimResults.find(d => d.aligned);
    const infra = result.dkimResults.find(d => !d.aligned);

    expect(aligned).toBeDefined();
    expect(aligned.domain).toBe("amazon.com");
    expect(infra).toBeDefined();
    expect(infra.domain).toBe("amazonses.com");
  });

  test("SPF fail / DKIM fail / DMARC fail", () => {
    const header = `spf=fail; dkim=fail header.i=@evil.com; dmarc=fail`;
    const from = "spoof@legit.com";

    const result = parseAuthResults(header, from);

    expect(result.spf).toBe("fail");
    expect(result.dmarc).toBe("fail");
    expect(result.dkimResults[0].result).toBe("fail");
  });

  test("DMARC ポリシー p=quarantine を取得", () => {
    const header = `spf=pass; dmarc=pass (p=quarantine) header.from=example.com`;
    const from = "user@example.com";

    const result = parseAuthResults(header, from);

    expect(result.dmarcPolicy).toBe("quarantine");
  });

  test("DMARC ポリシー p=reject を取得", () => {
    const header = `spf=pass; dmarc=pass (p=reject) header.from=example.com`;
    const from = "user@example.com";

    const result = parseAuthResults(header, from);

    expect(result.dmarcPolicy).toBe("reject");
  });

  test("認証ヘッダが空の場合、各フィールドは none", () => {
    const result = parseAuthResults("", "user@example.com");

    expect(result.spf).toBe("none");
    expect(result.dmarc).toBe("none");
    expect(result.dmarcPolicy).toBeNull();
    expect(result.dkimResults).toHaveLength(0);
  });

  test("DKIM 署名なしでも他の結果は正常に返る", () => {
    const header = `spf=pass; dmarc=pass`;
    const result = parseAuthResults(header, "user@example.com");

    expect(result.dkimResults).toHaveLength(0);
    expect(result.spf).toBe("pass");
  });

  test("DKIM の aligned フラグ: ドメイン不一致のとき false", () => {
    const header = `dkim=pass header.i=@amazonses.com`;
    const from = "user@amazon.com";

    const result = parseAuthResults(header, from);

    expect(result.dkimResults[0].aligned).toBe(false);
  });

  test("fromDomain の大文字小文字を正規化して比較", () => {
    const header = `dkim=pass header.i=@Example.com`;
    const from = "User@example.com";

    const result = parseAuthResults(header, from);

    expect(result.dkimResults[0].aligned).toBe(true);
  });
});
