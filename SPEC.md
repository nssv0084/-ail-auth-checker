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

#### パース

- `dmarc=(\w+)` で結果を抽出: `pass` / `fail` / `none`
- `dmarc=\w+\s*\([^)]*p=(\w+)` でポリシーを抽出: `none` / `quarantine` / `reject`
  - 括弧内にポリシーが記載されていない場合は `null`（ツールチップ表示なし）

#### 色分け

| 結果 | 色 | CSSクラス |
|---|---|---|
| `pass` | 緑 | `auth-pass` |
| `fail` | 赤 | `auth-fail` |
| `none` | グレー | `auth-none` |

- ポリシー（`p=`）はバッジの色に影響しない
- ポリシーが取得できた場合のみ `title` 属性に `ポリシー: p=xxx` を表示

#### DMARCポリシー（p=）

送信側が設定する、DMARC失敗時の受信側への推奨対応。受信側に強制力はない。

| p= | 意味 |
|---|---|
| `none` | 何もしない（モニタリング・移行期用） |
| `quarantine` | 迷惑メールフォルダへの振り分けを推奨 |
| `reject` | 受信拒否を推奨 |

#### DMARCがpassになる条件（OR条件）

| 経路 | 必要条件 |
|---|---|
| SPF経路 | `spf=pass` かつ smtp.mailfrom の組織ドメイン = From 組織ドメイン |
| DKIM経路 | `dkim=pass` かつ header.i の組織ドメイン = From 組織ドメイン |

どちらか一方が満たされれば `dmarc=pass`。バッジはどの経路でpassしたかを表示しない。
SPFアラインメントバッジとDKIMアラインメントバッジを組み合わせて読むことで判断できる。

#### 表示例

```
✓ SPF (em3513.mail.uccard.co.jp) [aligned]  ? DKIM (s13.y.mc.salesforce.com) [infra]  ✓ DMARC
```
→ SPF経路でDMARC pass。DKIMはSalesforceのインフラ署名で不一致。

```
✓ SPF (bounce.contact.babyrenta.com) [infra]  ✓ DKIM (babyrenta.com) [aligned]  ✓ DMARC
```
→ DKIM経路でDMARC pass。SPFのエンベロープFromは別サブドメインだが組織ドメイン一致。

```
? DKIM (amazonses.com) [infra]  ✗ DMARC
```
→ SPF/DKIMともアラインメントなし → DMARC fail。正規メールでも送信側の設定不備で起こる。

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
- DMARCがどの経路（SPF/DKIM）でpassしたかはバッジから直接読めない
- ドメイン取得日ヒューリスティックは「熟成」ドメインに無効
- ルックアライク検出・既知悪性ドメイン照合は未実装
