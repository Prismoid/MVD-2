# MVD Console

Minimum Viable Dataspace の管理用 PoC Console です。

## 起動

```bash
docker compose up --build
```

- Console: http://localhost:7651
- Console DB: container internal only (host port is not published)

## デザイン調整

この版は `style.css` のみを差し替えた、商用寄りの中間トーン版です。

- 機能・HTML構造・JavaScript・APIは変更していません。
- 黒基調の重さは避けつつ、ライト版よりも濃いブルーグレー系の商用ダッシュボード風に調整しています。
- 操作カードは白系で視認性を維持し、ヘッダー・タブ・Result表示に濃いアクセントを入れています。

## 前提

`CONNECTOR_URL` はデフォルトで `http://host.docker.internal:7550` です。
Connector API がホスト側で起動している前提です。

## 注意

PoC用です。秘密鍵は `mvd-console-db` の PostgreSQL に平文保存しています。本番用途では暗号化やKMS利用が必要です。


## Invoke Resource の任意ヘッダー

Invoke Resource では、HTTP Headers 欄に以下のように1行1件で任意ヘッダーを追加できます。

```text
X-Api-Key: demo-api-key
Accept: application/json
Content-Type: application/json
```

署名用の `X-Resource-Id` / `X-User-Id` / `X-Expire-Time` / `X-Signature` と `Authorization` は専用処理で扱うため、HTTP Headers 欄では指定しません。
