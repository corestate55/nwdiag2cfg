"""整合性チェック（ナレッジ 7章）のうち、図の中間表現に対して行うもの。

コンフィグを生成した後の自己点検（V-08、V-09、L-07）は selfcheck.py。
"""
import ipaddress
import re
from collections import Counter, defaultdict

from . import extract as X
from .build import norm_name, seg_ident, _port_sort


# ---------------------------------------------------------------- L2 グラフ
def l2_edges(M, carried=None):
    """セグメント（同一性キー）ごとの L2 リンク一覧 [(devA, devB, portA, portB, link)]

    carried(port) -> 所属セグメントキーの集合。省略時は図の所属（Po は Po 単位）。
    サーバー・AP は L2 をブリッジしない端末として扱う。
    """
    if carried is None:
        def carried(p):
            return set(p.eff_memb())
    res = defaultdict(list)
    seen = set()
    for lk in M.links:
        a, b = lk.a, lk.b
        if b is None or not a.dev.is_nw or not b.dev.is_nw:
            continue
        ua = a.po if a.po is not None else a
        ub = b.po if b.po is not None else b
        sig = tuple(sorted([(ua.dev.uid, ua.name), (ub.dev.uid, ub.name)]))
        if sig in seen:
            continue
        seen.add(sig)
        ka = {seg_ident(M, k) for k in carried(ua)}
        kb = {seg_ident(M, k) for k in carried(ub)}
        for k in ka & kb:
            res[k].append((ua.dev, ub.dev, ua, ub, lk))
    return res


def components(nodes, edges):
    par = {n: n for n in nodes}

    def f(x):
        while par[x] != x:
            par[x] = par[par[x]]
            x = par[x]
        return x
    for a, b in edges:
        par[f(a)] = f(b)
    return f


def loop_nodes(edges):
    """多重グラフの閉路に含まれる機器（次数1の葉を除いていった残り）"""
    adj = defaultdict(list)
    for i, (a, b) in enumerate(edges):
        adj[a].append((b, i))
        adj[b].append((a, i))
    alive = set(adj)
    deg = {n: len(adj[n]) for n in adj}
    changed = True
    while changed:
        changed = False
        for n in list(alive):
            if deg[n] <= 1:
                alive.discard(n)
                for m, i in adj[n]:
                    if m in alive:
                        deg[m] -= 1
                changed = True
    return alive


def detect_loops(M):
    """V-06。M.loops = {seg_ident: set(uid)}"""
    M.loops = {}
    groups = defaultdict(list)
    for k, es in l2_edges(M).items():
        nodes = loop_nodes([(a.uid, b.uid) for a, b, *_ in es])
        if nodes:
            M.loops[k] = nodes
            groups[frozenset(nodes)].append(k)
    for nodes, keys in groups.items():
        devs = sorted((M.dev(u) for u in nodes), key=lambda d: d.cfgname)
        names = sorted(_seg_label(M, k) for k in keys)
        kinds = []
        roles = {d.role for d in devs}
        if roles & {'fw', 'router'}:
            kinds.append('FW/RT の2ポートが同じ VLAN（%s）' % ', '.join(d.cfgname for d in devs if d.role in ('fw', 'router')))
        if any(d.role == 'l2sw' and 'mgmt' in d.cfgname for d in devs):
            kinds.append('管理SW経由の迂回')
        if any(d.role == 'l2sw' for d in devs) and len([d for d in devs if d.role == 'l3sw']) >= 2:
            kinds.append('コア間 LAG＋下位機器への二重接続（ラダー/三角）')
        if not kinds:
            kinds.append('機器間の閉路')
        stp_ng = [d.cfgname for d in devs if d.role == 'fw']
        f = M.F.add('V-06', 'WARN', ', '.join(names), 'L2 ループ: %s が閉路になる（%s）' % (
            ' / '.join(d.cfgname for d in devs), '、'.join(kinds)),
            basis='VLAN ごとに、両端が同じ VLAN を通すリンクでグラフを作り、閉路を検出',
            recommend='STP の設計（ルートブリッジ、ブロック位置）を確認する。%s' % (
                'ASA の BVI は STP に参加せず BPDU を転送するだけなので、コア側の STP でブロックされることを確認する' if stp_ng else ''),
            provisional='図の接続のまま設定（1.3 原則）。STP（%s）を有効にし、冗長ペアの01号機をルートにした' % M.project.get('stp_mode'),
            cells=[])
        for d in devs:
            f.attach(d.cfgname, None)
    M.F.ran('V-06')


def _seg_label(M, k):
    if k in M.segments:
        sg = M.segments[k]
        return '%s %s(VLAN%s)' % (sg.site, sg.name, sg.vlan_text())
    return str(k[1])


# ---------------------------------------------------------------- 各チェック
def run_checks(M):
    F = M.F
    nw = M.nw()
    _n_checks(M)
    _a05(M)
    _v_checks(M)
    _p_checks(M)
    _l_checks(M)
    _m_checks(M)
    _x_checks(M)
    _d_checks(M)
    F.ran('N-01', 'N-02', 'N-05', 'A-01', 'A-02', 'A-03', 'A-04', 'A-06', 'A-07', 'P-01', 'P-02', 'P-08', 'D-03', 'D-04',
          'L-04')
    return F


def _n_checks(M):
    # N-02: NW 機器の接頭辞（拠点）が接続先の多数派と違う
    for d in M.nw():
        sites = Counter()
        for pt in d.ports.values():
            for lk in pt.links:
                o = lk.other(pt)
                if o is not None and o.dev.is_nw and o.dev.pair is not d:
                    sites[o.dev.site] += 1
        if sites and d.site not in sites:
            s = sites.most_common(1)[0][0]
            M.F.add('N-02', 'WARN', d.cfgname, '%s 拠点の機器とだけつながっているが、接頭辞が %s' % (s, d.site),
                    recommend='ホスト名を確認する', cells=[d.label_id]).attach(d.cfgname)
    # N-03: 補助ページのホスト名
    if M.aux is not None and M.aux.hosts:
        main = {d.name for d in M.devices}
        stems = {re.sub(r'\d+$', '', n) for n in main}
        extra = sorted(h for h in M.aux.hosts if h not in main and re.sub(r'\d+$', '', h) not in stems
                       and _similar(h, main))
        missing = sorted(d.name for d in M.devices if d.cls in ('nw', 'ap') and d.name not in M.aux.hosts)
        if extra or missing:
            M.F.add('N-03', 'WARN', ', '.join(missing[:6] + extra[:6]),
                    '補助ページ「%s」と機器名が違う。合成図にだけある: %s。補助ページにだけある（似た名前）: %s' % (
                        M.aux.name, ', '.join(missing) or 'なし', ', '.join(extra) or 'なし'),
                    basis='ページ間で同じ機器の名前は揃うはず', recommend='どちらかの名前を直す',
                    provisional='合成図の名前で出力')
        M.F.ran('N-03')
    else:
        M.F.not_applicable('N-03', '補助ページの指定なし（--aux-tab）')
    # N-04: 枠の名前の重複（同じ拠点内）
    by = defaultdict(list)
    for text, rect, cid in M.raw.frames:
        site = _site_at(M, rect)
        by[(site, text)].append(cid)
    for (site, text), l in by.items():
        if len(l) > 1:
            M.F.add('N-04', 'INFO', '%s %s' % (site, text), 'ラック・フロアの名前「%s」が %d 回使われている' % (text, len(l)),
                    recommend='枠の名前を確認する', cells=l)
    M.F.ran('N-04')


def _similar(h, names):
    st = re.sub(r'\d+$', '', h)
    return any(st[:5] == re.sub(r'\d+$', '', n)[:5] for n in names)


def _site_at(M, rect):
    best = None
    for d in M.devices:
        if d.box:
            dx = abs((d.box[0] + d.box[2] / 2) - (rect[0] + rect[2] / 2))
            dy = abs((d.box[1] + d.box[3] / 2) - (rect[1] + rect[3] / 2))
            dist = dx + dy
            if best is None or dist < best[0]:
                best = (dist, d.site)
    return best[1] if best else '-'


def _a05(M):
    """冗長ペアの IP 規則（01/02/vip）: セグメント間の差と、補助ページの規則表記との差"""
    rules = {}
    for a in M.nw():
        if a.pair is None or not a.primary:
            continue
        b = a.pair
        for la in a.l3:
            lb = next((x for x in b.l3 if x.segkey == la.segkey), None)
            if lb is None or la.vip is None:
                continue
            sg = M.segments.get(la.segkey)
            rules[la.segkey] = ((la.badge_text or '?'), (lb.badge_text or '?'), '.%s' % la.vip, sg)
    aux_rules = _aux_rules(M)
    for k, (ra, rb, rv, sg) in rules.items():
        ar = aux_rules.get((norm_name(sg.name)[:4], sg.vlan))
        if ar and (ar[0] != ra or ar[1] != rb):
            M.F.add('A-05', 'WARN', '%s %s' % (sg.site, sg.name),
                    '合成図の 01/02/vip は %s/%s/%s、補助ページ「%s」の規則は %s/%s/%s' % (
                        ra, rb, rv, M.aux.name, ar[0], ar[1], ar[2]),
                    basis='同じセグメントの IP 規則はページ間で揃うはず', recommend='どちらの規則が正しいか確認して図を揃える',
                    provisional='合成図のバッジの値で設定', cells=sg.labels and [sg.labels[0][1]] or [])
    M.F.ran('A-05')


def _aux_rules(M):
    out = {}
    if M.aux is None:
        return out
    pat = re.compile(r'^(\.[^/\s]+)\s*/\s*(\.[^/\s]+)\s*/\s*(\.[^/\s(]+)\s*\(\s*01/02/vip\s*\)')
    for it in M.aux.page.items.values():
        if not (it.vertex and it.rect and it.text):
            continue
        m = pat.match(it.text.replace(' / ', '/'))
        if not m:
            continue
        cy = it.rect[1] + it.rect[3] / 2
        best = None
        for s in M.aux.segments:
            r = s['rect']
            if r[1] - 60 <= cy <= r[1] + r[3] + 60 and r[0] > it.rect[0] and r[0] - it.rect[0] < 700:
                d = abs((r[1] + r[3] / 2) - cy) + abs(r[0] - it.rect[0]) / 10
                if best is None or d < best[0]:
                    best = (d, s)
        if best:
            s = best[1]
            out.setdefault((norm_name(s['name'])[:4], s['vlan']), (m.group(1), m.group(2), m.group(3)))
    return out


def _v_checks(M):
    F = M.F
    # V-01: 同じ拠点で、違う名前のセグメントに同じ VLAN ID
    by = defaultdict(list)
    for sg in M.segments.values():
        if sg.vlan:
            by[(sg.site, sg.vlan)].append(sg)
    for (site, vl), l in by.items():
        if len({norm_name(s.name) for s in l}) > 1:
            F.add('V-01', 'ERROR', '%s VLAN%s' % (site, l[0].vlan_text()), '違うセグメントに同じ VLAN ID: %s' % ', '.join(
                s.name for s in l), recommend='VLAN ID を直す', cells=[c for s in l for c in s.items[:1]])
    F.ran('V-01', 'V-02')
    # V-03: ラベルの無い横線、線でつながらないラベル
    near = [(sid, v) for sid, v in M.raw.seg_label.items() if v[1] == 'near']
    if near:
        F.add('V-03', 'WARN', '%d 個のラベル' % len(near), '横線とラベルが線でつながっていない（近さで対応付けた）: %s' % ', '.join(
            M.page.items[v[0]].text for sid, v in near[:8]),
            recommend='ラベルと横線を点線でつなぐ', provisional='近い横線のラベルとして扱った',
            cells=[v[0] for sid, v in near])
    for sg in M.segments.values():
        if not sg.labels and sg.items and any(M.page.items[i].owner and M.dev_by_uid[M.page.items[i].owner].is_nw for i in sg.items) \
                and (sg.name or '').startswith('SEG_'):
            F.add('V-03', 'WARN', '%s %s' % (sg.site, sg.key[1]), 'ラベルの無い横線（同じ拠点の同じ色の横線にもラベルが無い）',
                  recommend='セグメント名・VLAN・アドレスのラベルを付ける', provisional='VLAN が不明なので所属を設定できない',
                  cells=sg.items[:3])
    F.ran('V-03')
    # V-04: リンク両端の所属の不一致
    seen = set()
    for lk in M.links:
        a, b = lk.a, lk.b
        if b is None or not a.dev.is_nw or not b.dev.is_nw:
            continue
        ua = a.po if a.po is not None else a
        ub = b.po if b.po is not None else b
        sig = tuple(sorted([(ua.dev.uid, ua.name), (ub.dev.uid, ub.name)]))
        if sig in seen:
            continue
        seen.add(sig)
        if ua.l3 is not None or ub.l3 is not None or (a.dev.role in ('fw', 'router') and a.l3) or (b.dev.role in ('fw', 'router') and b.l3):
            continue
        ka = {seg_ident(M, k) for k in ua.eff_memb()}
        kb = {seg_ident(M, k) for k in ub.eff_memb()}
        if ka != kb and ka and kb:
            only_a = ', '.join(_seg_label(M, k) for k in ka - kb) or 'なし'
            only_b = ', '.join(_seg_label(M, k) for k in kb - ka) or 'なし'
            f = F.add('V-04', 'ERROR', '%s %s ⇔ %s %s' % (ua.dev.cfgname, ua.name, ub.dev.cfgname, ub.name),
                      'リンク両端の VLAN 所属が違う（%s 側だけ: %s ／ %s 側だけ: %s）' % (ua.dev.cfgname, only_a, ub.dev.cfgname, only_b),
                      recommend='両端の所属線を揃える', provisional='それぞれ図のとおり設定', cells=[lk.edge])
            f.attach(ua.dev.cfgname, ua.name).attach(ub.dev.cfgname, ub.name)
    F.ran('V-04')
    # V-05: SVI を持つ機器から末端ポートまで到達できるか
    edges = l2_edges(M)
    for k, sg in M.segments.items():
        if not sg.vlan:
            continue
        gws = {d.uid for d in M.nw() for l3 in d.l3 if l3.segkey == k and l3.kind in ('svi', 'bvi')}
        ends = set()
        for d in M.nw():
            for pt in d.ports.values():
                if k in pt.eff_memb() and (not pt.links or any(lk.other(pt) is None or not lk.other(pt).dev.is_nw for lk in pt.links)):
                    ends.add(d.uid)
        if not gws or not ends:
            continue
        es = [(a.uid, b.uid) for a, b, *_ in edges.get(seg_ident(M, k), [])]
        f = components(gws | ends | {x for e in es for x in e}, es)
        roots = {f(g) for g in gws}
        lost = sorted(M.dev(u).cfgname for u in ends if f(u) not in roots)
        if lost:
            F.add('V-05', 'ERROR', '%s %s' % (sg.site, sg.name), '%s から GW（SVI）を持つ機器まで VLAN%s の L2 経路が無い' % (
                ', '.join(lost), sg.vlan_text()), recommend='途中のリンクの所属線を確認する', provisional='図のとおり設定')
    F.ran('V-05')
    # V-07: VRRP グループ番号の範囲
    for sg in M.segments.values():
        if sg.vip is not None and sg.vlan and sg.vlan[1] > 255 and M.project.get('fhrp_group') == 'vlan_id':
            F.add('V-07', 'WARN', '%s %s' % (sg.site, sg.name), 'VLAN%s をグループ番号にすると VRRP の範囲（1-255）を超える' % sg.vlan_text(),
                  recommend='グループ番号の規則を決める', provisional='グループ番号を <TBD> にした', cells=sg.items[:1])
    F.ran('V-07')


def _p_checks(M):
    F = M.F
    legend = M.cable_legend
    for dev in M.nw():
        for pt in dev.ports.values():
            if pt.kind == 'port' and not pt.links and pt.memb and pt.l3 is None and not pt.shutdown_reason \
                    and pt.po is None and not (dev.mgmt and dev.mgmt.get('port') is pt):
                F.add('P-01', 'INFO', '%s %s' % (dev.cfgname, pt.name), 'VLAN の所属線はあるが、物理リンクの線が無いポート',
                      basis='ポートから横線への線だけがある', recommend='対向の機器への線を描くか、予備なら所属線を消す',
                      provisional='所属どおり設定（description は「図に物理リンクの線なし」）',
                      cells=[pt.cell]).attach(dev.cfgname, pt.name)
    for lk in M.links:
        a, b = lk.a, lk.b
        thick = X.width_class(lk.width) == 'thick'
        for p in (a, b):
            if p is None or not p.dev.is_nw:
                continue
            if thick and p.name.lower().startswith('gi') and not getattr(p, 'name_warn', None):
                F.add('P-03', 'WARN', '%s %s' % (p.dev.cfgname, p.name), '1G のポート名だが太線（10G 系のケーブル）で接続',
                      recommend='ポート名か線種を直す', provisional='図のポート名で設定', cells=[lk.edge]).attach(p.dev.cfgname, p.name)
            if not thick and p.name.lower().startswith('te') and lk.mark_of(p) not in ('white',):
                o = lk.other(p)
                if o is not None and o.name.lower().startswith('gi'):
                    F.add('P-03', 'WARN', '%s %s' % (p.dev.cfgname, p.name),
                          '10G ポートに 1G 接続だが、変換モジュール（白丸）の記号が無い', recommend='端点記号を確認する',
                          cells=[lk.edge]).attach(p.dev.cfgname, p.name)
        if legend and b is not None:
            ca = legend.get((X.width_class(lk.width), lk.mark_of(a)))
            cb = legend.get((X.width_class(lk.width), lk.mark_of(b)))
            if ca and cb and ca['cable'] != cb['cable']:
                F.add('P-04', 'ERROR', '%s %s ⇔ %s %s' % (a.dev.cfgname, a.name, b.dev.cfgname, b.name),
                      '両端のケーブル種別が違う（%s / %s）' % (ca['cable'], cb['cable']), recommend='端点記号を確認する',
                      cells=[lk.edge])
    F.ran('P-03', 'P-04')
    # P-05: 型番末尾のポート数
    for d in M.nw():
        m = re.search(r'-(\d{2})\b', d.model or '')
        if not m:
            continue
        n = int(m.group(1))
        mx = 0
        for pt in d.ports.values():
            mm = re.search(r'/(\d+)(?:-(\d+))?$', pt.name)
            if mm:
                mx = max(mx, int(mm.group(2) or mm.group(1)))
        if mx > n:
            F.add('P-05', 'WARN', d.cfgname, 'ポート番号 %d が型番の末尾（-%d）のポート数を超える' % (mx, n),
                  recommend='機種かポート番号を確認する', cells=[d.label_id])
    F.ran('P-05')
    # P-06 / P-07: LAG
    done = set()
    for d in M.nw():
        for po in d.ports.values():
            if po.kind != 'po' or not po.members:
                continue
            peers = set()
            peer_pos = set()
            for m in po.members:
                for lk in m.links:
                    o = lk.other(m)
                    if o is not None:
                        peers.add(o.dev.cfgname)
                        peer_pos.add(o.po.name if o.po is not None else None)
            if len(peers) > 1:
                F.add('P-06', 'WARN', '%s %s' % (d.cfgname, po.name), 'LAG のメンバーが別々の機器（%s）につながる' % ', '.join(sorted(peers)),
                      recommend='MLAG/スタックの構成か、図の誤りかを確認する', cells=[po.cell]).attach(d.cfgname, po.name)
            if len(peers) == 1:
                peer = M.F  # noqa
                pd = next(x for x in M.nw() if x.cfgname == list(peers)[0]) if any(x.cfgname in peers for x in M.nw()) else None
                if pd is None or not pd.is_nw:
                    continue
                sig = tuple(sorted([(d.cfgname, po.name), (pd.cfgname, str(sorted(p for p in peer_pos if p)))]))
                if None in peer_pos:
                    F.add('P-07', 'WARN', '%s %s' % (d.cfgname, po.name), '対向 %s のポートが LAG（Po）に入っていない' % pd.cfgname,
                          recommend='対向側にも Po を描く', cells=[po.cell]).attach(d.cfgname, po.name)
                elif len(peer_pos) == 1:
                    ppn = list(peer_pos)[0]
                    pp = pd.ports.get(ppn)
                    if pp is not None and len(pp.members) != len(po.members):
                        F.add('P-07', 'WARN', '%s %s ⇔ %s %s' % (d.cfgname, po.name, pd.cfgname, ppn),
                              'LAG のメンバー数が両端で違う（%d / %d）' % (len(po.members), len(pp.members)), cells=[po.cell, pp.cell])
                    elif ppn != po.name and (pd.cfgname, ppn, d.cfgname, po.name) not in done:
                        done.add((d.cfgname, po.name, pd.cfgname, ppn))
                        F.add('P-07', 'INFO', '%s %s ⇔ %s %s' % (d.cfgname, po.name, pd.cfgname, ppn),
                              'LAG の番号が両端で違う', basis='動作には影響しない', recommend='番号を揃える運用なら図を直す',
                              cells=[po.cell, pp.cell if pp else None])
    F.ran('P-06', 'P-07')


def _l_checks(M):
    F = M.F
    # L-01: 末端のあるセグメントに GW が無い
    for k, sg in M.segments.items():
        if not sg.vlan:
            continue
        has_gw = any(l3.segkey == k for d in M.nw() for l3 in d.l3 if l3.kind in ('svi', 'bvi', 'phys'))
        ends = any(k in pt.eff_memb() for d in M.nw() for pt in d.ports.values()
                   if any(lk.other(pt) is None or not lk.other(pt).dev.is_nw for lk in pt.links))
        if ends and not has_gw and not any(d.mgmt and d.mgmt.get('segkey') == k for d in M.nw()):
            F.add('L-01', 'WARN', '%s %s' % (sg.site, sg.name), '端末のつながるセグメントに L3（GW）が無い',
                  recommend='GW を描く（意図して閉じたセグメントなら対応不要）', cells=sg.items[:1])
    # L-02: ペアの片方にしか SVI が無い
    for a in M.nw():
        if a.pair is None or not a.primary or not a.routings:
            continue
        b = a.pair
        ka = {l3.segkey for l3 in a.l3 if l3.kind == 'svi'}
        kb = {l3.segkey for l3 in b.l3 if l3.kind == 'svi'}
        for k in ka ^ kb:
            sg = M.segments.get(k)
            only = a if k in ka else b
            F.add('L-02', 'WARN', '%s ⇔ %s %s' % (a.cfgname, b.cfgname, sg.name if sg else k),
                  '冗長ペアの %s にだけ L3（バッジ）がある' % only.cfgname, recommend='もう片方のバッジを描く',
                  provisional='図のとおり片方だけ設定').attach(only.cfgname)
    # L-03: 冗長化プロトコル
    leg = ' '.join(M.raw.legend_texts)
    notes = ' '.join(n.text for n in M.raw.notes) + ' ' + (' '.join(M.aux.texts) if M.aux else '')
    pl = {p for p in ('VRRP', 'HSRP', 'GLBP') if p in leg}
    pn = {p for p in ('VRRP', 'HSRP', 'GLBP') if p in notes}
    if pl and pn and pl != pn:
        F.add('L-03', 'INFO', '冗長化プロトコル', '凡例は %s、注記・補助ページは %s' % ('/'.join(pl), '/'.join(pn)),
              provisional='凡例の %s を採用' % '/'.join(pl))
    F.ran('L-01', 'L-02', 'L-03')
    _l05(M)
    if M.project.services:
        _l06(M)
    else:
        F.not_applicable('L-06', '管理サービス（NTP/DNS/Syslog）の IP が図にも既定値ファイルにも無い')


def _l05(M):
    """全 L3 機器から全セグメント（拠点間を含む）へ、接続経路＋静的経路で届くか"""
    F = M.F
    targets = [sg for sg in M.segments.values() if sg.vlan and sg.cidr and not sg.cidr_tbd]
    owner_of_ip = {}
    for d in M.nw():
        for l3 in d.l3:
            sg = M.segments.get(l3.segkey) if l3.segkey else None
            if sg is None or not sg.cidr or sg.cidr_tbd or sg.aggregate:
                continue
            n = ipaddress.ip_network(sg.cidr, strict=False)
            if l3.host is not None:
                owner_of_ip[str(n.network_address + l3.host)] = d
            elif M.project.ipam_for(d.cfgname, sg.name):
                owner_of_ip[str(M.project.ipam_for(d.cfgname, sg.name)).split('/')[0]] = d
            if l3.vip is not None:
                owner_of_ip.setdefault(str(n.network_address + l3.vip), d)

    def connected(d, net):
        for l3 in d.l3:
            if l3.vrf is not None:
                continue
            sg = M.segments.get(l3.segkey) if l3.segkey else None
            if sg is not None and sg.cidr and not sg.cidr_tbd and ipaddress.ip_network(sg.cidr, strict=False).overlaps(net):
                return True
        return False

    def lookup(d, net):
        best = None
        for r in d.routes:
            if r.vrf is not None or r.dest.startswith('<'):
                continue
            rn = ipaddress.ip_network(r.dest, strict=False)
            if rn.version == net.version and (net.subnet_of(rn)):
                if best is None or rn.prefixlen > best[0].prefixlen:
                    best = (rn, r)
        return best[1] if best else None

    missing = defaultdict(set)
    unknown = defaultdict(set)
    l3devs = [d for d in M.nw() if any(l3.kind in ('svi', 'bvi', 'phys') and l3.vrf is None for l3 in d.l3)
              and d.role in ('l3sw', 'fw', 'router')]
    for d in l3devs:
        for sg in targets:
            net = ipaddress.ip_network(sg.cidr, strict=False)
            cur, hops, ok = d, 0, False
            visited = set()
            while hops < 8 and cur is not None and cur.uid not in visited:
                visited.add(cur.uid)
                if connected(cur, net):
                    ok = True
                    break
                r = lookup(cur, net)
                if r is None:
                    break
                if r.nh.startswith('<'):
                    ok = None
                    break
                cur = owner_of_ip.get(r.nh)
                hops += 1
            if ok is False:
                missing[(cur.cfgname if cur else d.cfgname, sg.site)].add(sg.name)
            elif ok is None:
                unknown[(d.cfgname, sg.site)].add(sg.name)
    for (dn, site), names in sorted(missing.items()):
        blk = M.site_block.get(site)
        F.add('L-05', 'WARN', '%s → %s 拠点' % (dn, site), '%s から %s 拠点のセグメント（%s）への経路が無い' % (
            dn, site, ', '.join(sorted(names))),
            basis='接続セグメントと静的経路（%s）でたどった結果' % ('論理構成図の矢印' if M.aux else '既定値ファイル。補助ページの指定なし'),
            recommend='追加案: 宛先 %s、next-hop は経路上の隣接機器（冗長ペアなら VIP）。図に経路を描くか、既定値ファイルの routes に書く' % (
                blk[0] if blk else '<拠点ブロック>'),
            provisional='経路は足していない（5.5）').attach(dn)
    if unknown:
        F.add('L-05', 'INFO', '%d 経路' % sum(len(v) for v in unknown.values()),
              'next-hop が <TBD> の経路があり、その先の到達性は確認できない（%s）' % ', '.join(
                  '%s→%s' % k for k in sorted(unknown)[:6]),
              recommend='TBD を埋めてから再実行する')
    M.F.ran('L-05')


def _l06(M):
    M.F.ran('L-06')


def _m_checks(M):
    F = M.F
    nomg = [d for d in M.nw() if d.mgmt is None and not any(l3.segkey and 'MGMT' in norm_name(M.segments[l3.segkey].name)
                                                          for l3 in d.l3 if l3.segkey in M.segments)]
    if nomg:
        nomg = sorted(nomg, key=lambda d: d.cfgname)
        F.add('M-01', 'WARN', ', '.join(d.cfgname for d in nomg), '管理用のバッジ・Mgmt ポート・管理 VLAN の SVI のどれも無い機器',
              recommend='管理経路（OOB の Mgmt ポートか、管理セグメントの IP）を図に描く',
              provisional='管理 IF は設定していない（データ面の IF 経由で管理する前提）', cells=[d.label_id for d in nomg])
    # M-02: インバンド管理で、管理 VLAN を通すアップリンクが1本だけ
    for d in M.nw():
        if not d.mgmt or d.mgmt['kind'] != 'inband':
            continue
        k = d.mgmt['segkey']
        ups = set()
        for pt in d.ports.values():
            if k in pt.eff_memb():
                for lk in pt.links:
                    o = lk.other(pt)
                    if o is not None and o.dev.is_nw and o.dev is not d.pair:
                        ups.add(o.dev.cfgname)
        if len(ups) == 1 and d.pair is None:
            F.add('M-02', 'WARN', d.cfgname, '管理通信が %s への1本のリンクにだけ依存する' % list(ups)[0],
                  recommend='冗長化が必要か確認する')
    # M-03
    by = defaultdict(set)
    for d in M.nw():
        if d.mgmt and d.mgmt.get('segkey'):
            by[seg_ident(M, d.mgmt['segkey'])].add(d.mgmt['kind'])
    for k, kinds in by.items():
        if 'inband' in kinds and kinds & {'oob', 'r12'}:
            F.add('M-03', 'INFO', _seg_label(M, k), '同じ管理セグメントに OOB（管理 VRF）とインバンドの機器が混在',
                  recommend='OOB 機器から GRT 側への到達経路（管理 VRF の default の向き先）を確認する')
    # M-04
    if not M.project.services:
        F.add('M-04', 'INFO', '管理サービス', 'NTP/DNS/Syslog/SNMP サーバーの IP が図にも既定値ファイルにも無い',
              recommend='既定値ファイルの services に書く', provisional='ntp / logging を <TBD> で出力')
    F.ran('M-01', 'M-02', 'M-03', 'M-04')


def _x_checks(M):
    F = M.F
    if M.aux is None:
        for c in ('X-01', 'X-02', 'X-03'):
            F.not_applicable(c, '補助ページの指定なし（--aux-tab）')
        return
    # X-01: セグメントの一致
    for sg in M.segments.values():
        if not sg.vlan:
            continue
        blk = M.site_block.get(sg.site)
        cand = [a for a in M.aux.segments if a['vlan'] == sg.vlan and norm_name(a['name'])[:4] == norm_name(sg.name)[:4]]
        if blk:
            cand2 = [a for a in cand if a['cidr'] and ipaddress.ip_network(a['cidr'], strict=False).subnet_of(blk[0])]
            cand = cand2 or cand
        if not cand:
            continue
        a = cand[0]
        orig = next((l[0]['cidr'] for l in sg.labels if l[0]['cidr']), None)
        if orig and a['cidr'] and orig != a['cidr']:
            F.add('X-01', 'WARN', '%s %s' % (sg.site, sg.name), '合成図は %s、補助ページ「%s」は %s' % (orig, M.aux.name, a['cidr']),
                  recommend='どちらかを直す', provisional='%s を採用（%s）' % (sg.cidr if not sg.cidr_tbd else '<TBD>', sg.cidr_src),
                  cells=[sg.labels[0][1], a['id']])
        if a['name'] != sg.name and norm_name(a['name']) != norm_name(sg.name):
            F.add('X-01', 'INFO', '%s %s' % (sg.site, sg.name), 'セグメント名の表記が違う（合成図 %s / 補助ページ %s）' % (sg.name, a['name']),
                  cells=[sg.labels[0][1] if sg.labels else None, a['id']])
    F.ran('X-01')
    if '物理' in M.aux.name and '論理' not in M.aux.name:
        F.ran('X-02')
    else:
        F.not_applicable('X-02', '物理構成図ページの指定なし')
    F.not_applicable('X-03', 'カラー版だけで処理する設定（D12）')


def _d_checks(M):
    F = M.F
    legend = M.cable_legend
    if legend:
        odd = []
        for lk in M.links:
            if lk.b is None:
                continue
            for p in (lk.a, lk.b):
                key = (X.width_class(lk.width), lk.mark_of(p))
                if key not in legend:
                    odd.append((lk, p, key))
        if odd:
            F.add('D-01', 'INFO', '%d 本の線' % len({o[0].edge for o in odd}),
                  '凡例に無い線種・端点記号の組合せ: %s' % ', '.join(sorted({'%s/%s' % o[2] for o in odd})),
                  recommend='凡例に追加するか線種を直す', cells=[o[0].edge for o in odd])
        F.ran('D-01')
    else:
        F.not_applicable('D-01', '凡例（Connector / Cable）が見つからない')
    F.not_applicable('D-02', '線の経路の交差は本ツールでは判定しない（目視で確認）')
