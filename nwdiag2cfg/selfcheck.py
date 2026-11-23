"""生成したコンフィグの自己点検（ナレッジ 7.3 V-08 / V-09、7.5 L-07）。

コンフィグの文字列を簡易パースし直し、図から作ったポート所属表と突き合わせる。
描画部の誤りもここで検出できるように、図の所属は描画部を通さずに中間表現から直接作る。
"""
import re
from collections import defaultdict

from .build import seg_ident
from .checks import components

TBD_RE = re.compile(r'<TBD:[^>]*>')


def parse_cfg(text):
    """interface ごとの dict(mode, vlans:set(int), tokens:set(str), shutdown, bridge)"""
    out = {}
    cur = None
    for raw in text.splitlines():
        line = raw.split(' ! ')[0].rstrip()
        if line.startswith('!'):
            continue
        m = re.match(r'^interface (?:range )?(.+)$', line)
        if m:
            cur = dict(mode=None, vlans=set(), tokens=set(), shutdown=False, bridge=None)
            out[m.group(1).strip()] = cur
            continue
        if not line.startswith(' '):
            cur = None
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r'^switchport access vlan (.+)$', s)
        if m:
            cur['mode'] = 'access'
            _vl(cur, m.group(1))
        m = re.match(r'^switchport trunk allowed vlan (.+)$', s)
        if m:
            cur['mode'] = 'trunk'
            _vl(cur, m.group(1))
        m = re.match(r'^bridge-group (\d+)$', s)
        if m:
            cur['mode'] = 'access'
            cur['bridge'] = int(m.group(1))
            cur['vlans'].add(int(m.group(1)))
        if s == 'shutdown':
            cur['shutdown'] = True
    return out


def _vl(cur, spec):
    for tok in TBD_RE.findall(spec):
        cur['tokens'].add(tok)
    spec = TBD_RE.sub('', spec)
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-')
            cur['vlans'].update(range(int(a), int(b) + 1))
        elif part.isdigit():
            cur['vlans'].add(int(part))


def run_selfcheck(M, cfgs):
    F = M.F
    parsed = {name: parse_cfg(c.text()) for name, c in cfgs.items()}
    M.parsed = parsed
    port_if = {}  # Port -> (cfgname, ifname)
    for name, c in cfgs.items():
        for ifn, pt in c.ifmap.items():
            port_if[id(pt)] = (name, ifn)
            if pt.kind == 'po':
                for m in pt.members:
                    pass

    def cfg_of(pt):
        k = port_if.get(id(pt))
        if k is None:
            return None
        return parsed[k[0]].get(k[1])

    # ---- V-09: 全ポートで図の所属とコンフィグを突き合わせる
    unexplained = []
    for dev in M.nw():
        for pt in dev.ports.values():
            if pt.l3 is not None or pt.kind == 'virtual':
                continue
            exp_keys = pt.eff_memb()
            if not exp_keys:
                continue
            pc = cfg_of(pt)
            if pc is None:
                unexplained.append((dev, pt, '図では所属があるが、コンフィグにインターフェースが無い'))
                continue
            if pc['shutdown']:
                M.diffs.append(dict(dev=dev.cfgname, port=pt.name, diagram=_names(M, exp_keys), cfg='shutdown',
                                    why=pt.shutdown_reason or '予備（R14）', fid=None))
                continue
            exp = set()
            for k in exp_keys:
                sg = M.segments.get(k)
                if sg and sg.vlan:
                    exp.update(range(sg.vlan[0], sg.vlan[1] + 1))
            got = pc['vlans']
            missing = exp - got
            extra = got - exp
            explained = []
            for k in exp_keys:
                sg = M.segments.get(k)
                if sg and sg.aggregate and set(range(sg.vlan[0], sg.vlan[1] + 1)) & missing:
                    tok = [t for t in pc['tokens'] if sg.name in t]
                    if tok:
                        missing -= set(range(sg.vlan[0], sg.vlan[1] + 1))
                        explained.append('%s の範囲 → %s（%s）' % (sg.vlan_text(), tok[0],
                                         '払い出し単位' if '@' in tok[0] else 'access に範囲は書けない'))
            if explained:
                M.diffs.append(dict(dev=dev.cfgname, port=pt.name, diagram=_names(M, exp_keys),
                                    cfg=', '.join(explained), why='5.4 集約 VLAN の扱い', fid=None))
            if missing or extra:
                unexplained.append((dev, pt, '図にあってコンフィグに無い VLAN: %s ／ 図に無いのにコンフィグにある VLAN: %s' % (
                    _rng(missing) or 'なし', _rng(extra) or 'なし')))
    for dev, pt, msg in unexplained:
        F.add('V-09', 'ERROR', '%s %s' % (dev.cfgname, pt.name), msg, basis='生成したコンフィグを再パースして図の所属と比較',
              recommend='ツールの不具合の可能性。model.json（--debug）を確認する').attach(dev.cfgname, pt.name)
    F.ran('V-09')

    # ---- V-08: SVI の VLAN がどのポートにも出ていない
    for name, c in cfgs.items():
        dev = c.dev
        if dev.os != 'iosxe' and dev.os != 'isr':
            continue
        allv, toks = set(), set()
        for ifn, pc in parsed[name].items():
            if not pc['shutdown']:
                allv |= pc['vlans']
                toks |= pc['tokens']
        for ifn, vid in c.svis:
            if vid.isdigit():
                ok = int(vid) in allv
            else:
                sgname = vid[5:].split('_VLAN')[0]
                sg = next((s for s in M.segments.values() if s.name == sgname and s.site == dev.site), None)
                ok = sg is not None and (bool(set(range(sg.vlan[0], sg.vlan[1] + 1)) & allv) or any(sgname in t for t in toks))
            if not ok:
                F.add('V-08', 'ERROR', '%s %s' % (name, ifn), 'SVI %s の VLAN がこの機器のどのポート・Po にも出ていない' % ifn,
                      basis='この SVI は誰とも通信できない', recommend='図の所属線を確認する（図の不足か、生成ミス）').attach(name, None)
    F.ran('V-08')

    # ---- L-07: 冗長ペアのセグメントの L2 連続性（コンフィグから作ったグラフ）
    for a in M.nw():
        b = a.pair
        if b is None or not a.primary:
            continue
        for la in a.l3:
            if la.vip is None or la.kind != 'svi':
                continue
            sg = M.segments.get(la.segkey)
            if sg is None or not sg.vlan:
                continue
            vid = sg.vlan[0]
            es = []
            via = defaultdict(list)
            seen = set()
            for lk in M.links:
                p, q = lk.a, lk.b
                if q is None or not p.dev.is_nw or not q.dev.is_nw:
                    continue
                cp, cq = cfg_of(p), cfg_of(q)
                if cp is None or cq is None or cp['shutdown'] or cq['shutdown']:
                    continue
                if _carries(cp, vid, sg) and _carries(cq, vid, sg):
                    sig = tuple(sorted([p.dev.uid, q.dev.uid])) + (lk.edge,)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    es.append((p.dev.uid, q.dev.uid))
                    via[frozenset([p.dev.uid, q.dev.uid])].append(lk)
            direct = frozenset([a.uid, b.uid]) in via
            nodes = {x for e in es for x in e} | {a.uid, b.uid}
            f = components(nodes, es)
            if f(a.uid) != f(b.uid):
                F.add('L-07', 'ERROR', '%s ⇔ %s %s' % (a.cfgname, b.cfgname, sg.name),
                      'VRRP を組む VLAN%s が2台の間で L2 的につながっていない' % sg.vlan_text(),
                      basis='生成したコンフィグの access/trunk から VLAN ごとのグラフを作って確認',
                      recommend='コア間 trunk（Po）にこの VLAN を通すか、図の構成を確認する。つながらないと両方がマスターになる',
                      provisional='図のとおり設定').attach(a.cfgname, None).attach(b.cfgname, None)
            elif not direct:
                path = _path(M, es, a.uid, b.uid)
                mids = [M.dev(u) for u in path[1:-1]]
                kinds = {d.role for d in mids}
                F.add('L-07', 'WARN' if kinds & {'fw', 'router'} else 'INFO', '%s ⇔ %s %s' % (a.cfgname, b.cfgname, sg.name),
                      'VRRP を組む VLAN%s は2台の直接の trunk には無く、%s を経由してだけつながる' % (
                          sg.vlan_text(), ' → '.join(d.cfgname for d in mids)),
                      basis='生成したコンフィグの access/trunk から VLAN ごとのグラフを作って確認',
                      recommend='経由する機器が VRRP の通知（マルチキャスト）と BPDU を転送するか、STP のブロック位置で経路が切れないかを確認する。'
                                '直接つなぐならコア間 Po にこの VLAN を通す',
                      provisional='図のとおり設定').attach(a.cfgname, None)
    F.ran('L-07')


def _carries(pc, vid, sg):
    if vid in pc['vlans']:
        return True
    return sg.aggregate and any(sg.name in t for t in pc['tokens'])


def _path(M, es, s, t):
    adj = defaultdict(set)
    for a, b in es:
        adj[a].add(b)
        adj[b].add(a)
    prev = {s: None}
    q = [s]
    while q:
        x = q.pop(0)
        if x == t:
            break
        for y in sorted(adj[x]):
            if y not in prev:
                prev[y] = x
                q.append(y)
    path = []
    x = t
    while x is not None:
        path.append(x)
        x = prev.get(x)
    return list(reversed(path))


def _names(M, keys):
    return ', '.join('%s(%s)' % (M.segments[k].name, M.segments[k].vlan_text()) for k in keys if k in M.segments)


def _rng(s):
    s = sorted(s)
    out = []
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[j] + 1:
            j += 1
        out.append(str(s[i]) if i == j else '%d-%d' % (s[i], s[j]))
        i = j + 1
    return ','.join(out)
