# nwdiag2cfg

物理・論理合成図（drawio）から、NW 機器のコンフィグとレビュー指摘を生成する CLI です。
AI を介さず、`図からコンフィグ変換ナレッジ.md`（v1.1）の規則をそのままコードにしています。

- 入力: drawio ファイル（`.drawio` / `.drawio.svg` / `.xml`、圧縮ページも可）の「物理・論理合成図」タブ
- 出力: コンフィグ（Cisco IOS-XE / ISR / ASA 記法）、変換レポート、指摘一覧（Markdown と CSV）
- 動作環境: Linux、bash、Python 3.11 以上（標準ライブラリのみ。追加パッケージ不要）

## 使い方

```bash
# タブ名の確認
bin/nwdiag2cfg -f diagrams.drawio.svg --list-tabs

# 生成（出力先は ./diagrams/）
bin/nwdiag2cfg -f diagrams.drawio.svg -t 物理・論理合成図_4C

# 論理構成図も読ませる（経路・アドレスの照合・X-01〜03 に使う）
bin/nwdiag2cfg -f diagrams.drawio.svg -t 物理・論理合成図_4C --aux-tab 論理構成図_4C

# 設計ルール（既定値ファイル）を指定し、前回のレビュー結果を引き継ぐ
bin/nwdiag2cfg -f diagrams.drawio.svg -t 物理・論理合成図_4C -p project.toml \
  --prev-review diagrams.prev/review.csv --force
```

`pip install .` すると `nwdiag2cfg` コマンドとしても使えます。`python3 -m nwdiag2cfg ...` でも動きます。

| オプション | 内容 |
|---|---|
| `-f FILE` | 入力の drawio ファイル（必須） |
| `-t TAB` | 物理・論理合成図のタブ名 |
| `-o DIR` | 出力先（既定: `./<入力ファイル名の語幹>`） |
| `--aux-tab TAB` | 補助ページ（論理構成図など）。複数指定可。指定したときだけ読む |
| `-p FILE` | 既定値ファイル（TOML）。例: [docs/project.example.toml](docs/project.example.toml) |
| `--force` | 出力先が既にあるとき、消して作り直す |
| `--prev-review CSV` | 前回の `review.csv`。同じ指摘（キーが同じ）の状態・確認者・メモを引き継ぐ |
| `--fail-on error\|warn\|never` | 指摘がこの重要度以上なら終了コード 1（CI 用。既定 never） |
| `--debug` | `debug/model.json`（中間表現）と `debug/extract.md`（図の読み取り結果）も出す |
| `--list-tabs` | タブ名の一覧を出して終わる |
| `-q` | 要約を表示しない |

終了コード: `0` 生成できた（指摘があっても 0）／ `1` `--fail-on` の条件に当たった／ `2` 入力エラー（ファイル・タブが無い、出力先が既にある等）。

## 出力

```
<output_dir>/
├── review.md        指摘一覧（レビューシート）とチェックの実施結果
├── review.csv       同じ内容の CSV（UTF-8 BOM 付き。Excel で開いて状態・メモを記入できる）
├── configs.md       変換レポート（機種判定、台帳、結線表、ポート所属表、機器ごとの根拠、推測、TBD、図との差分）
├── configs/
│   └── <機器名>.cfg  機器ごとのコンフィグ
└── debug/           --debug のとき
```

- 図から決まらない値は `<TBD:名前>` のまま有効な設定行として出します（コメントアウトしません）。一覧は configs.md の 6 章です。
- 懸念のある行には `! WARN R-012` のように review の指摘 ID を付けます。
- 図の読み方・推測の根拠は行末の `! 【図】` `! 【推測】` `! 【論】`（補助ページ） `! 【指定】`（既定値ファイル） `! 【一般】` で示します。
- 指摘のキー（review.csv の「キー」列）は、チェック ID・対象・図形 ID から作るので、図を直して再実行しても同じ指摘は同じキーになります。

## 図の描き方の前提

ナレッジ v1.1 の表現規約に従った図を前提にしています（色＝セグメント、GRT/vrf の箱＝ルーティングテーブル、`.N` のバッジ＝IP の第4オクテット、凡例の線種＝ケーブル種別、冗長ペアの片方の省略、など）。
カラー版のみ対象です（モノクロ版のラベル照合 X-03 は行いません）。

## 制限

- 出力の記法は Cisco 系 3 種（IOS-XE スイッチ、ISR、ASA）だけです。機種名から判定できない場合もこの 3 種に寄せます（D11）。
- `router_same_segment` は `switchport_svi` のみ、`pair_output` は `full` のみ対応です。
- 線の交差による曖昧さ（D-02）は判定しません。

## 開発

```bash
python3 -m pytest -q          # または python3 -m unittest discover -s tests -t .
python3 tests/fixtures/make_fixtures.py   # 合成図 tests/fixtures/lab.drawio を作り直す
```

`tests/test_samples.py` は書籍・セミナーの図での回帰テストです。図のファイルが無い環境ではスキップします
（場所は環境変数 `NWDIAG2CFG_BOOK` / `NWDIAG2CFG_SEMINAR` で指定）。

ソースの構成:

| モジュール | 役割 |
|---|---|
| `drawio.py` | drawio の読込（圧縮ページの展開、絶対座標、回転） |
| `extract.py` | 図形の分類（機器・ポート・横線・ラベル・バッジ・ルーティング箱）と線の分類 |
| `aux.py` | 補助ページ（論理構成図）の読取り（セグメント・注記・経路矢印） |
| `build.py` | 中間表現の構築と推論（冗長ペア、対称性、未接続線、L3、VRRP、アドレス矛盾、集約 VLAN） |
| `routes.py` | 静的経路（補助ページの矢印、既定値ファイル、管理経路） |
| `checks.py` | チェック（N/A/V/P/L/M/X/D） |
| `render.py` | コンフィグの生成 |
| `selfcheck.py` | 生成したコンフィグを読み直して図と突き合わせる（V-08 / V-09 / L-07） |
| `report.py` | configs.md / review.md / review.csv |
| `project.py` | 既定値ファイル（TOML）とナレッジの既定値 |

## ライセンス

MIT License（[LICENSE](LICENSE)）
