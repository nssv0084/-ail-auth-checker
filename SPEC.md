# Mail Auth Checker 仕様

バージョン: 0.2.4

## 概要

Thunderbird拡張機能。メールを開くと `Authentication-Results` ヘッダーを解析し、
SPF/DKIM/DMARCの認証結果とアラインメントをバナーで表示する。

## バナー表示

メール本文の上部に以下を表示する。

### SPFバッジ

- `smtp.mailfrom` / `smtp.helo` からエンベロープFromドメインを抽出
- アラインメント: エンベロープFromの組織ドメイン = ヘッダーFromの組織ドメイン
- 一致: 強調表示（`auth-aligned`）
- 不一致: 控えめ表示（`auth-infra`）
- `smtp.mailfrom` がない場合: ドメイン表示なしでSPF結果のみ

### DKIMバッジ（複数対応）

- `header.i=@domain` から署名ドメインを抽出
- `header.i=user@domain` 形式（ローカルパート付き）も対応
- `(コメント)` を含むヘッダーも正しくパース
- アラインメント: 署名ドメインの組織ドメイン = ヘッダーFromの組織ドメイン
- 一致: 強調表示（`auth-aligned`）、不一致: 控えめ表示（`auth-infra`）
- Fromと一致するDKIMを優先表示、インフラ署名は後ろに並べる

### DMARCバッジ

- `p=` ポリシーをツールチップで表示

### 送信元ドメイン注釈

- ヘッダーFromのドメインをテキスト表示

### ドメイン取得日（非同期）

- SPF/DKIM/DMARCバッジを先に表示し、RDAP取得後に差し替え
- `.com` / `.net`: Verisign RDAPで取得日・有効期限を表示
  - 30日未満: 赤（`auth-fail`）
  - 180日未満: 黄（`auth-warn`）
  - 180日以上: 緑（`auth-pass`）
- その他TLD: WHOIS検索リンクを表示
- 取得日データは24時間キャッシュ（`messenger.storage.local`）

## アラインメント判定

組織ドメイン（eTLD+1）で比較（Relaxedアラインメント相当）。

```
em3513.mail.uccard.co.jp → uccard.co.jp
mail.uccard.co.jp        → uccard.co.jp → 一致
```

2段階TLD対応: `.co.jp` `.or.jp` `.ne.jp` `.co.uk` `.com.au` など。

## SPF結果の色分け

| 結果 | 色 |
|---|---|
| `pass` | 緑 |
| `fail` | 赤 |
| `softfail` | 黄 |
| `neutral` / `none` | グレー |

## RDAP制約

`rdap.jprs.jp`（`.jp`）はCORS非対応のためfetchがブロックされる。
`.jp`ドメインはWHOIS検索リンクにフォールバック。

## ファイル構成

| ファイル | 役割 |
|---|---|
| `parser.js` | 純粋関数（`parseAuthResults` / `extractDomain` / `getOrgDomain`） |
| `background.js` | メッセージ受信・RDAP取得・content scriptへのメッセージ送信 |
| `content.js` | バナーDOM生成・UPDATE_RDAPによる差し替え |
| `content.css` | バッジスタイル |
| `test/test.js` | Node.jsで実行するユニットテスト（外部依存なし） |

## テスト実行

```
node test/test.js
```

## 既知の限界

- 認証pass/failは送信者の善意を証明しない
- DMARCポリシーは送信者が設定するため、`p=none` では受信側に強制力なし
- ドメイン取得日ヒューリスティックは「熟成」ドメインに無効
- ルックアライク検出・既知悪性ドメイン照合は未実装
