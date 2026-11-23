"""configs.md（変換レポート）、review.md / review.csv（指摘一覧）の出力（ナレッジ 8章）。"""
import csv
import io
import ipaddress
import re
from collections import defaultdict

from . import extract as X
from .build import _port_sort
from .findings import CHECK_IDS
from .render import port_vlan_items, vlan_list, long_name

HOW = {'edge': '所属線【図】', 'label': 'ラベルへの線【図】(D-04)', 'dangling': '未接続線を推定【推測】(P-01)',
       'symmetry': '冗長ペアの対称性【推測：対称性】', 'server': 'サーバー側の所属【図】(R16)', 'badge': 'IP バッジ【図】',
       'r12': 'Mgmt ポート（R12）【推測】', 'override': '既定値ファイル【指定】'}
ROLE = {'fw': 'FW', 'router': 'ルーター', 'l3sw': 'L3SW', 'l2sw': 'L2SW', 'ap': '無線AP', 'server': 'サーバー', 'other': 'その他'}
COLS = ['ID', '重要度', 'チェックID', 'ページ', '対象', '図の位置', '図の記載', '問題', '根拠', '推奨対応', 'コンフィグでの暫定扱い',
        '状態', '確認者・日付', 'メモ', 'キー']


def esc(s):
    return str(s if s is not None else '').replace('|', '\\|').replace('\n', ' ')


def table(head, rows):
    out = ['| ' + ' | '.join(head) + ' |', '|' + '---|' * len(head)]
    for r in rows:
        out.append('| ' + ' | '.join(esc(x) for x in r) + ' |')
    return out


# ---------------------------------------------------------------- TBD
TBD_RE = re.compile(r'<TBD:[^>]*>')


def tbd_need(tok):
    t = tok.upper()
    if 'POLICY' in t:
        return 'セキュリティポリシー'
    if 'NTP' in t or 'SYSLOG' in t:
        return '運用設計（管理サーバーの IP）'
    if 'TUNNEL' in t or 'IPSEC' in t:
        return 'VPN 設計（対向・暗号）'
    if 'GW' in t and ('INTERNET' in t or 'ISP' in t or 'INET' in t):
        return '回線契約（ISP 側 GW）'
    if '_VLAN@' in t:
        return '設計ルール（単位ごとの VLAN 払い出し）'
    if '_VLAN' in t or 'GROUP' in t:
        return '設計ルール（VLAN ID / VRRP グループ）'
    if '_IP' in t or 'MASK' in t or 'CIDR' in t or 'VIP' in t or 'GW' in t or 'PREFIX' in t or 'NET' in t:
        return 'IP 管理表'
    return '設計者'


def collect_tbd(cfgs):
    rows = []
    for name in sorted(cfgs):
        for line in cfgs[name].text().splitlines():
            if line.startswith('!'):
                continue
            body = line.split(' ! ')[0]
            for tok in TBD_RE.findall(body):
                rows.append((name, body.strip(), tok, tbd_need(tok)))
    return rows


# ---------------------------------------------------------------- configs.md
def configs_md(M, cfgs, meta):
    L = ['# %s コンフィグ生成レポート' % meta['stem'], '']
    L += ['- 入力: `%s`（sha256: `%s`）' % (meta['file'], meta['sha256'][:16]),
          '- 対象タブ: 「%s」' % meta['tab'],
          '- 補助タブ: %s' % ('、'.join('「%s」' % a for a in meta['aux']) if meta['aux'] else 'なし（--aux-tab 未指定。経路・X-01〜03 は対象外）'),
          '- 既定値ファイル: %s' % (meta['project'] or 'なし（すべてナレッジ v1.1 の既定値）'),
          '- ツール: nwdiag2cfg %s（ナレッジ v1.1 準拠）' % meta['version'],
          '- 作成日: %s' % meta['date'], '']
    errs = [f for f in M.F.items if f.sev == 'ERROR']
    L += ['## 0. 要約', '',
          '- コンフィグ: %d 台（`configs/`）。無線AP・サーバーは対象外（9章）' % len(cfgs),
          '- 指摘: ERROR %d / WARN %d / INFO %d 件（review.md）' % tuple(
              len([f for f in M.F.items if f.sev == s]) for s in ('ERROR', 'WARN', 'INFO')),
          '- 未確定値（<TBD>）: %d 箇所（6章）' % len(collect_tbd(cfgs)), '']
    if errs:
        L += ['**ERROR の指摘**', '']
        for f in errs:
            L.append('- %s %s %s: %s（暫定: %s）' % (f.id, f.check, f.target, f.problem, f.provisional or '-'))
        L.append('')
    # 1. 機種判定
    L += ['## 1. 機種判定', '']
    rows = []
    for d in sorted(M.nw(), key=lambda d: d.cfgname):
        os_ = {'iosxe': 'Cisco IOS-XE（Catalyst 9000 相当）', 'isr': 'Cisco IOS-XE（ISR 相当）', 'asa': 'Cisco ASA'}[d.os]
        rows.append((d.cfgname, d.model, d.platform['judge'], os_, d.platform['reason']))
    L += table(['機器', '図の記載', '判定', '採用した記法', '理由'], rows) + ['']
    # 2. 台帳
    L += ['## 2. 抽出サマリ', '', '### 2.1 機器台帳', '']
    rows = []
    for d in sorted(M.devices, key=lambda d: (d.site, d.cfgname)):
        rows.append((d.cfgname, d.name if d.name != d.cfgname else '', d.model, ROLE[d.role], d.site,
                     d.pair.cfgname if d.pair else '', 'コンフィグ' if d.is_nw else ('設定項目表' if d.cls == 'ap' else '対象外'),
                     d.label_id))
    L += table(['機器', '図のホスト名（仮称のとき）', '機種', '役割', '拠点', '冗長ペア', '出力', 'cell'], rows) + ['']
    L += ['### 2.2 セグメント台帳', '']
    rows = []
    for sg in sorted(M.segments.values(), key=lambda s: (s.site, s.vlan or (99999, 0), s.name)):
        ips = []
        for d in sorted(M.nw(), key=lambda d: d.cfgname):
            for l3 in d.l3:
                if l3.segkey == sg.key:
                    ips.append('%s %s' % (d.cfgname, l3.badge_text or '-'))
        cidr = '<TBD>' if sg.cidr_tbd else (sg.cidr or '-')
        unit = ''
        if sg.aggregate:
            unit = ('%s（%s）' % (sg.unit['text'], sg.unit['source'])) if sg.unit else '注記なし'
        rows.append((sg.site, sg.color, sg.name, sg.vlan_text() or '-', cidr, sg.cidr_src if sg.cidr else '',
                     '.%d' % sg.vip if sg.vip is not None else '', '; '.join(ips), unit))
    L += table(['拠点', '色', '名前', 'VLAN', 'アドレス', '出所', 'VIP', 'L3（バッジ）', '払い出し単位'], rows) + ['']
    L += ['### 2.3 結線表', '']
    rows = []
    for lk in sorted(M.links, key=lambda l: (l.a.dev.cfgname, _port_sort(l.a.name))):
        a, b = lk.a, lk.b
        leg = M.cable_legend.get((X.width_class(lk.width), lk.mark_of(a)))
        rows.append(('%s %s' % (a.dev.cfgname, a.name), _mk(lk.mark_of(a)),
                     '%s %s' % (b.dev.cfgname, b.name) if b else lk.ext_name, _mk(lk.mark_of(b) if b else lk.mark_ext),
                     lk.width, leg['cable'] if leg else '', (a.po.name if a.po else '') + ('/' + b.po.name if b and b.po else ''),
                     lk.edge + (' (推定)' if lk.inferred else '')))
    L += table(['A', '端点A', 'B', '端点B', '線幅', 'ケーブル（凡例）', 'LAG', '線 cell'], rows) + ['']
    L += ['### 2.4 ポート所属表（図から作った表。V-09 の基準）', '']
    rows = []
    for d in sorted(M.nw(), key=lambda d: d.cfgname):
        for pt in sorted(d.ports.values(), key=lambda p: _port_sort(p.name)):
            if pt.po is not None:
                continue
            m = pt.eff_memb()
            if not m and pt.l3 is None:
                continue
            if pt.l3 is not None:
                sg = M.segments.get(pt.l3.segkey) if pt.l3.segkey else None
                rows.append((d.cfgname, pt.name, 'L3' + ('（vrf %s）' % pt.l3.vrf if pt.l3.vrf else ''), sg.name if sg else '-', HOW.get(pt.l3.how, pt.l3.how)))
                continue
            mode, items, notes = port_vlan_items(M, pt)
            hows = sorted({HOW.get(x.how, x.how) for x in m.values()})
            rows.append((d.cfgname, pt.name + ('（%s）' % ','.join(x.name for x in pt.members) if pt.members else ''),
                         mode or '-', vlan_list(items) if items else '-', '、'.join(hows)))
    L += table(['機器', 'ポート', 'モード', 'VLAN', '根拠'], rows) + ['']
    # 3. 機器別
    L += ['## 3. 機器別コンフィグ', '']
    for name in sorted(cfgs):
        c = cfgs[name]
        d = c.dev
        L += ['### 3.%s %s（%s、%s）' % (sorted(cfgs).index(name) + 1, name, d.model, ROLE[d.role]), '',
              'ファイル: `configs/%s.cfg`' % name, '', '```', c.text().rstrip(), '```', '']
        L += table(['#', '設定', '図の何を見たか / どう判断したか', '根拠ラベル', '指摘ID'], evidence_rows(M, d)) + ['']
    # 4. 推測
    L += ['## 4. 推測で補った項目', '']
    L += table(['#', '機器', '項目', '採用値', '推論の根拠', '確認すべき人/情報'],
               [(i + 1, g['dev'], g['item'], g['value'], g['reason'], g['who']) for i, g in enumerate(M.guesses)]) + ['']
    # 5. 既定値
    L += ['## 5. 既定値を使った項目（既定値ファイルで未指定だった項目）', '']
    L += table(['#', '項目', '採用した既定値', '説明', 'ナレッジの参照箇所', '影響する機器'],
               [(i + 1, u['key'], u['value'], u['desc'], u['ref'], ', '.join(sorted(u['devices'])))
                for i, u in enumerate(M.project.used_default)]) + ['']
    # 6. TBD
    L += ['## 6. 未確定値（TBD）一覧', '', '`<TBD:...>` は有効な設定行のまま置いているので、すべて**投入前に置換が必要**です（構文エラーになるため置換漏れに気付けます）。'
          '同じ識別子は同じ値に置き換えてください（対向・冗長ペアで一致させる値）。', '']
    rows = collect_tbd(cfgs)
    L += table(['#', '機器', '設定行', 'プレースホルダ', '必要な情報', '投入前に置換'],
               [(i + 1, r[0], r[1], r[2], r[3], '必須') for i, r in enumerate(rows)]) + ['']
    by = defaultdict(set)
    for r in rows:
        by[r[3]].add(r[2])
    L += ['**決める情報源ごとのまとめ**', '']
    for k in sorted(by):
        L.append('- %s: %s' % (k, ', '.join('`%s`' % t for t in sorted(by[k]))))
    L.append('')
    # 7. 差分
    L += ['## 7. 図との差分（図と違う設定にした箇所。V-09 の結果）', '']
    v09 = M.F.by_check('V-09')
    L += table(['#', '機器', 'ポート/項目', '図の記載', 'コンフィグ', '理由'],
               [(i + 1, x['dev'], x['port'], x['diagram'], x['cfg'], x['why']) for i, x in enumerate(M.diffs)]) + ['']
    L += ['理由の記載が無い差分: %s' % ('%d 件（review.md の V-09）' % len(v09) if v09 else 'なし'), '']
    # 8. チェック実施結果
    L += ['## 8. チェック実施結果', '']
    L += check_table(M) + ['']
    # 9. 対象外
    L += ['## 9. 対象外とした要素', '', '### 9.1 無線AP の設定項目表（コンフィグは作らない。ナレッジ 1.2）', '']
    rows = []
    for d in sorted([d for d in M.devices if d.cls == 'ap'], key=lambda d: d.cfgname):
        for pt in d.ports.values():
            for lk in pt.links:
                o = lk.other(pt)
                if o is None:
                    continue
                mode, items, notes = port_vlan_items(M, o)
                badge = ', '.join('%s（%s）' % (b[3], _segname(M, d.site, b[1])) for b in _badges(M, d))
                rows.append((d.cfgname, d.model, '%s %s' % (o.dev.cfgname, o.name), 'PoE' if ('PoE' in o.note or True) else '',
                             '%s %s' % (mode or '-', vlan_list(items) if items else '-'), badge or '-',
                             'SSID と VLAN の対応、管理 IP、コントローラー'))
    L += table(['AP', '機種', '接続先', '給電', 'スイッチ側の VLAN', '管理IP（バッジ）', '未確定事項'], rows) + ['']
    L += ['### 9.2 サーバー・その他', '']
    rows = [(d.cfgname, d.model, ROLE[d.role], 'スイッチ側の所属の根拠と、描画ミスのチェックにだけ使用')
            for d in sorted(M.devices, key=lambda d: d.cfgname) if d.cls in ('server', 'other')]
    L += table(['機器', '機種', '役割', '扱い'], rows) + ['']
    return '\n'.join(L) + '\n'


def _mk(m):
    return {'black': '●', 'white': '○'}.get(m, '-')


def _badges(M, d):
    from .build import _badges_of
    return _badges_of(M, d)


def _segname(M, site, color):
    sg = M.segments.get((site, color))
    return sg.name if sg else color


def _fids(M, dev, port=None):
    return ', '.join(f.id for f in M.F.items if (dev.cfgname, port) in f.refs)


def evidence_rows(M, d):
    rows = []

    def add(what, why, label, fid=''):
        rows.append((len(rows) + 1, what, why, label, fid))
    host = 'Host 欄「%s / %s」（cell %s）' % (d.name, d.model, d.label_id)
    if d.cfgname != d.name:
        host += '。同名の機器があるため仮称'
    add('hostname %s' % d.cfgname, host, '【図】' + ('【推測】' if d.cfgname != d.name else ''), _fids(M, d))
    add('記法（%s）' % d.os, d.platform['reason'], '【推測】' if d.platform['judge'] == '特定不能' else '【図】')
    for l3 in d.l3:
        sg = M.segments.get(l3.segkey) if l3.segkey else None
        if sg is None:
            continue
        what = {'svi': 'interface Vlan%s' % (sg.vlan_text() if sg.vlan and not sg.aggregate else '<TBD>'),
                'bvi': 'interface BVI（%s）' % '+'.join(m.name for m in l3.members),
                'phys': 'interface %s（L3）' % (l3.port.name if l3.port else '-'),
                'mgmt': '管理 IF %s' % (l3.port.name if l3.port else '')}.get(l3.kind, l3.kind)
        why = []
        why.append({'edge': 'ルーティング箱（%s）と %s の横線が線でつながる' % (l3.vrf or 'GRT', sg.name),
                    'symmetry': '冗長ペアの %s と同じ構成（%s の箱では線が省略）' % (d.pair.cfgname if d.pair else '-', d.cfgname),
                    'badge': '%s の色の IP バッジがある' % sg.name,
                    'dangling': '未接続線を推定して GRT と %s の接続とした' % sg.name,
                    'r12': 'Mgmt ポートが管理SWにつながるが vrf 箱もバッジも無い（R12）'}.get(l3.how, l3.how))
        if sg.cidr_tbd:
            why.append('アドレスは <TBD>（重複・拠点外のため）')
        elif sg.cidr:
            why.append('アドレス %s%s' % (sg.cidr, sg.cidr_src))
        if l3.badge_text:
            why.append('バッジ %s' % l3.badge_text + ('（値が未確定なので <TBD>）' if l3.host is None else ''))
        if l3.vip is not None:
            why.append('vip .%d（%s）' % (l3.vip, 'VRRP'))
        if l3.kind == 'bvi':
            why.append('同じ横線に2ポート（%s）がつながるので BVI（R10、4.2）' % '・'.join(m.name for m in l3.members))
        if l3.kind == 'svi' and d.role == 'router':
            why.append('同じ横線に2ポートがつながるのでスイッチポート＋SVI（R10、4.2）')
        lab = '【図】' + ('【論】' if sg.cidr_src == '【論】' else '') + ('【推測】' if l3.how in ('symmetry', 'dangling', 'r12') or l3.kind in ('bvi',) else '')
        add(what, '。'.join(why), lab, _fids(M, d, None))
    for pt in sorted(d.ports.values(), key=lambda p: _port_sort(p.name)):
        if pt.po is not None or pt.l3 is not None:
            continue
        m = pt.eff_memb()
        if not m and not pt.shutdown_reason and '予備' not in pt.note:
            continue
        if pt.shutdown_reason or '予備' in pt.note:
            add('%s shutdown' % pt.name, pt.shutdown_reason or '図に「%s」と明示（R14）' % pt.note, '【図】', _fids(M, d, pt.name))
            continue
        mode, items, notes = port_vlan_items(M, pt)
        hows = sorted({HOW.get(x.how, x.how) for x in m.values()})
        segs = '・'.join(M.segments[k].name for k in m if k in M.segments)
        peer = []
        for x in ([pt] + pt.members):
            for lk in x.links:
                o = lk.other(x)
                if o is not None:
                    peer.append('%s %s' % (o.dev.cfgname, o.name))
        why = '%s が %s の横線に所属（%s）' % (pt.name, segs, '、'.join(hows))
        if pt.members:
            why += '。Po 箱が %s にまたがる（R5）' % '・'.join(x.name for x in pt.members)
        if peer:
            why += '。対向 %s' % ', '.join(sorted(set(peer)))
        if notes:
            why += '。' + '。'.join(notes)
        lab = '【図】' + ('【推測：対称性】' if any(x.how == 'symmetry' for x in m.values()) else '') + \
            ('【推測】' if any(x.how in ('dangling',) for x in m.values()) else '')
        add('%s %s %s' % (pt.name, mode, vlan_list(items)), why, lab, _fids(M, d, pt.name))
    if d.mgmt:
        mg = d.mgmt
        why = {'oob': 'vrf 箱（%s）と Mgmt ポート → OOB 管理' % mg.get('vrf'),
               'inband': '管理セグメントの横線上にバッジだけがある → インバンド管理（SVI）',
               'r12': 'Mgmt ポートが管理SWにつながるが vrf 箱もバッジも無い → 管理 VRF に入れる（R12）'}[mg['kind']]
        add('管理（%s）' % mg['kind'], why, '【図】' if mg['kind'] != 'r12' else '【推測】')
    for r in d.routes:
        add('route %s → %s%s' % (r.dest, r.nh, ' (vrf %s)' % r.vrf if r.vrf else ''), r.reason, r.src)
    return rows


def check_table(M):
    rows = []
    for cid, title in CHECK_IDS:
        fs = M.F.by_check(cid)
        if fs:
            res = '該当あり（%s）' % ', '.join(f.id for f in fs)
        elif cid in M.F.na:
            res = '対象外（%s）' % M.F.na[cid]
        elif cid in M.F.done:
            res = '該当なし'
        else:
            res = '対象外（未実施）'
        rows.append((cid, title, res))
    return table(['チェックID', '内容', '結果'], rows)


# ---------------------------------------------------------------- review
def review_rows(M):
    rows = []
    for f in M.F.items:
        rows.append([f.id, f.sev, f.check, f.page, f.target, f.cell_text(), f.diagram, f.problem, f.basis, f.recommend,
                     f.provisional, f.status, f.reviewer, f.memo, f.key])
    return rows


def review_md(M, meta):
    L = ['# %s 指摘一覧（レビューシート）' % meta['stem'], '',
         '- 入力: `%s` / タブ「%s」%s' % (meta['file'], meta['tab'], ' / 補助タブ: %s' % '、'.join(meta['aux']) if meta['aux'] else ''),
         '- 作成日: %s / nwdiag2cfg %s' % (meta['date'], meta['version']),
         '- 件数: ERROR %d / WARN %d / INFO %d' % tuple(len([f for f in M.F.items if f.sev == s]) for s in ('ERROR', 'WARN', 'INFO')),
         '- 「状態」「確認者・日付」「メモ」は人が記入します。CSV（review.csv）に記入して `--prev-review` で次回に引き継げます。',
         '- 図形の探し方: drawio で「編集 > 検索」（Ctrl+F）でラベルを検索するか、「その他 > 図の編集」で XML を開き cell id で検索します。', '']
    L += ['## 1. 指摘一覧', '']
    L += table(COLS[:-1], [r[:-1] for r in review_rows(M)]) + ['']
    L += ['## 2. チェック実施結果', ''] + check_table(M) + ['']
    others = M.raw.edges.get('other', []) + [e for e in M.raw.edges.get('free', [])]
    L += ['## 3. 目視で確認してほしい箇所', '',
          '- 分類できなかった線: %d 本（凡例の線、冗長ペア線、図形どうしの線など）。`--debug` の extract.md に一覧があります。' % len(others),
          '- 線の交差（D-02）は本ツールでは判定していません。', '']
    return '\n'.join(L) + '\n'


def review_csv(M):
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator='\r\n')
    w.writerow(COLS)
    for r in review_rows(M):
        w.writerow(r)
    return '\ufeff' + buf.getvalue()


def load_prev_review(path):
    out = {}
    with open(path, encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            k = row.get('キー')
            if k:
                out[k] = row
    return out
