# MVD の使い方

## メインアプリ: MVD Console

http://localhost:7651

「Public Key Registry」画面で、ユーザーを登録します。

1. UserID を入力し、「Generate User」をクリックします。
2. その後、「Register」ボタンで公開鍵を作成・登録します。

下部には、生成されたローカルキーが表示されます。

「Federated Catalog」画面では、アセットを登録できます。

- API の場合は、「Endpoint」フィールドに URL を入力します。
- ファイルを提供する場合は、ファイルサーバ上で提供可能なファイル (少なくとも1つ) を使用します。Resource Path には `http://host.docker.internal:7552/hello_world.txt` を指定します。

「Authorization」画面では、オファーを作成できます。

- どのユーザーが、どのリソースを、どのユーザーに提供するかを入力します。
- 有効期限も入力する必要があります。形式は `2099-12-31T23:59:59` です。

「Invoke Resource」画面では、提供されたリソースを取得できます。

- リソースを取得したいユーザーを入力します。
- Resource ID を入力します。
- メソッドを入力します (例: GET または POST)。
- 必要に応じて、クエリパラメータも入力します。
- 必要に応じて、ヘッダーも入力します。
- Authorization type を選択し、必要に応じて認証情報を入力します。
- POST リクエストの場合は、必要に応じて body も入力できます。

## Federated Catalog & Public Key Registry

http://localhost:7650/

「Federated Catalog」画面では、リソースの一覧を確認し、検索・フィルタリングできます。

「Public Key Registry」画面では、公開鍵を検索できます (ID を入力します)。