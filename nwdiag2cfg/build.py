"""図の分類結果から中間表現を作り、ナレッジ 4〜6章の規則で推論・正規化する。"""
import ipaddress
import re
from collections import Counter, defaultdict

from . import extract as X
from .drawio import rect_gap
from .findings import Evidence
from .model import Device, Port, Membership, Segment, Link, L3If

GRAY = {'#808080', '#666666', '#999999', '#B3B3B3'}

KNOWN_VENDORS = [
    (r'\bCisco\b|Catalyst|Nexus|\bISR\b|\bASR\b|\bASA\b|Firepower', 'Cisco'),
    (r'Juniper|\bEX\d{3,4}|\bSRX\d|\bMX\d', 'Juniper'),
    (r'Forti(Gate|Switch)|Fortinet', 'Fortinet'),
    (r'Palo\s*Alto|\bPA-\d', 'Palo Alto'),
    (r'Aruba|\bCX\s*\d{4}', 'Aruba'),
    (r'Arista|\b7\d{3}[A-Z]', 'Arista'),
    (r'Yamaha|\bRTX\d|\bSWX\d', 'Yamaha'),
    (r'NEC|\bIX\d{4}|QX-', 'NEC'),
    (r'Allied|\bAT-x', 'Allied Telesis'),
]


def norm_name(n):
    return re.sub(r'[^A-Z0-9]', '_', (n or '').upper())


def stem(name):
    base = re.sub(r'-dup\d+$', '', name)
    return re.sub(r'\d+$', '', base)


def num(name):
    base = re.sub(r'-dup\d+$', '', name)
    m = re.search(r'(\d+)$', base)
    return int(m.group(1)) if m else 0


class Model:
    def __init__(self, raw, project, findings):
        self.raw = raw
        self.page = raw.page
        self.project = project
        self.F = findings
        self.devices = []
        self.dev_by_uid = {}
        self.segments = {}          # (site,color) -> Segment
        self.links = []
        self.port_by_cell = {}
        self.evidence = defaultdict(list)   # cfgname -> [Evidence]
        self.guesses = []           # 推測一覧: dict(dev, item, value, reason, who)
        self.diffs = []             # 図との差分
        self.excluded = []          # 対象外とした要素
        self.aux = None             # 補助ページの情報
        self.site_block = {}
        self.site_names = {}        # 拠点名（東京）-> site
        self.cable_legend = raw.legend
        self.dangling_done = set()

    # ------------------------------------------------------------------ 共通
    def dev(self, uid):
        return self.dev_by_uid.get(uid)

    def nw(self):
        return [d for d in self.devices if d.is_nw]

    def seg(self, key):
        return self.segments.get(key)

    def guess(self, dev, item, value, reason, who='設計者'):
        self.guesses.append(dict(dev=dev, item=item, value=value, reason=reason, who=who))

    def ev(self, dev, what, reason, labels=('【図】',), cells=(), findings=()):
        self.evidence[dev.cfgname if hasattr(dev, 'cfgname') else dev].append(
            Evidence(what, reason, labels, cells, [f.id if hasattr(f, 'id') else f for f in findings]))


# ====================================================================== 構築
def build(raw, project, findings, aux=None):
    M = Model(raw, project, findings)
    M.aux = aux
    _devices(M)
    _ports(M)
    _segments(M)
    _links(M)
    _memberships(M)
    _pairs(M)
    _dangling(M, 'link')
    _symmetry(M)
    _server_side(M)
    _dangling(M, 'seg')
    _l3(M)
    _orphan_labels(M)
    _vrrp(M)
    _addresses(M)
    _aggregates(M)
    return M


# ---------------------------------------------------------------- 機器・役割
def _role(model_text, has_routing, has_segments):
    t = model_text or ''
    if re.search(r'L2\s*-?\s*switch|L2SW|L2スイッチ', t, re.I):
        return 'l2sw'
    if re.search(r'firewall|ファイアウォール|\bFW\b|UTM', t, re.I):
        return 'fw'
    if re.search(r'router|ルータ', t, re.I):
        return 'router'
    if re.search(r'L3\s*-?\s*switch|L3SW|L3スイッチ', t, re.I):
        return 'l3sw'
    if re.search(r'\bAP\b|wi-?fi|無線|access\s*point', t, re.I):
        return 'ap'
    if re.search(r'server|サーバ|linux|hypervisor|\bVM\b|windows', t, re.I):
        return 'server'
    if re.search(r'L2\s*-?\s*switch|L2SW|L2スイッチ|switch|スイッチ', t, re.I):
        return 'l3sw' if has_routing else 'l2sw'
    if has_routing and has_segments:
        return 'l3sw'
    if has_segments:
        return 'l2sw'
    return 'other'


def _devices(M):
    p = M.page
    for d in M.raw.devices:
        cfgname = d['name'] if d['dup_index'] == 1 else '%s-dup%d' % (d['name'], d['dup_index'])
        dv = Device(d['uid'], d['name'], cfgname, d['model'], d['label_id'], d['box'], d['box_id'])
        M.devices.append(dv)
    # owner は extract で uid=name を付けているので、dup を区別して付け直す
    by_box = {dv.box_id: dv for dv in M.devices if dv.box_id}
    for it in p.items.values():
        o = getattr(it, '_dev', None)
        it.owner = by_box.get(o['box_id']).uid if o and o.get('box_id') in by_box else None
    for dv in M.devices:
        M.dev_by_uid[dv.uid] = dv
    for it in p.items.values():
        if it.owner is None:
            continue
        dv = M.dev_by_uid[it.owner]
        if it.kind == 'routing':
            dv.routings.append(it)
        elif it.kind == 'segment':
            dv.seg_items.append(it)
    for dv in M.devices:
        dv.role = _role(dv.model, any(r.text == 'GRT' for r in dv.routings), bool(dv.seg_items))
        dv.cls = {'fw': 'nw', 'router': 'nw', 'l3sw': 'nw', 'l2sw': 'nw', 'ap': 'ap', 'server': 'server'}.get(dv.role,
                                                                                                         'other')
        dv.site = dv.cfgname.split('-')[0]
    # 重複ホスト名
    names = defaultdict(list)
    for dv in M.devices:
        names[dv.name].append(dv)
    for n, l in names.items():
        if len(l) > 1:
            ren = ', '.join('%s → %s' % (x.name, x.cfgname) for x in l[1:])
            f = M.F.add('N-01', 'WARN', n, '同じホスト名の機器が %d 台ある' % len(l),
                        basis='機器の Host 欄が同じ文字列',
                        recommend='図のホスト名を一意に直す（命名規則に合わせた番号・ラック名など）',
                        provisional='2台目以降は仮称 `%s` で出力（ファイル名も仮称）' % ren if any(x.is_nw for x in l)
                        else '対象外の機器（サーバー等）なのでコンフィグへの影響なし',
                        cells=[x.label_id for x in l], diagram=n)
            for x in l[1:]:
                if x.is_nw:
                    M.guess(x.cfgname, 'hostname', x.cfgname, '図のホスト名 %s が重複しているため自動の仮称（D7）' % x.name)
    # 機種判定
    for dv in M.devices:
        if not dv.is_nw:
            continue
        spec = M.project.platform_for(dv.cfgname)
        vendor = None
        for pat, v in KNOWN_VENDORS:
            if re.search(pat, dv.model or ''):
                vendor = v
                break
        fb = {'l3sw': 'iosxe', 'l2sw': 'iosxe', 'router': 'isr', 'fw': 'asa'}[dv.role]
        if spec:
            dv.os = spec
            dv.platform = dict(judge='指定', reason='既定値ファイルの platform で指定', vendor=vendor)
        elif vendor and vendor != 'Cisco':
            dv.os = fb
            dv.platform = dict(judge='特定（%s）' % vendor,
                               reason='%s の記法は未対応（D11）。Cisco 記法で出力するため、実機の記法への変換が必要' % vendor,
                               vendor=vendor)
            M.F.add('P-05', 'WARN', dv.cfgname, '機種 %s は Cisco 以外（%s）だが、Cisco 記法で出力した' % (dv.model, vendor),
                    basis='本ツールは Cisco フォールバックの3記法だけに対応（D11）',
                    recommend='実機の記法に変換する', provisional='Cisco 記法', cells=[dv.label_id], diagram=dv.model)
        elif vendor == 'Cisco':
            dv.os = fb
            dv.platform = dict(judge='特定（Cisco）', reason='Vendor Model に Cisco 系の名前がある', vendor=vendor)
        else:
            dv.os = fb
            dv.platform = dict(judge='特定不能', reason=_fallback_reason(dv), vendor=None)
    # サーバーの拠点（つながる NW 機器の拠点）は _links の後で直す
    return M


def _fallback_reason(dv):
    why = '図の Vendor Model「%s」は実在のベンダー名・型番として読めない' % (dv.model or '(空欄)')
    sel = {
        'l3sw': 'L3スイッチ（ルーティング箱＋横線）として SVI・VRRP・Port-channel・VRF を標準的に書ける Catalyst 9000 系 IOS-XE を採用',
        'l2sw': 'L2スイッチとして Catalyst 9200/9300 系 IOS-XE を採用（管理用 VRF の概念がある）',
        'router': 'ルーターとして静的経路・スイッチポート＋SVI を書ける ISR（IOS-XE）を採用',
        'fw': 'ファイアウォールとして ASA 記法を採用（同一セグメントの2ポートを BVI で表現できる）',
    }[dv.role]
    fix = '機種確定後にポート番号体系・管理IF名・冗長化プロトコルの書式を見直す'
    return '%s。%s。ポート名の形式（Te/Gi/Po）も Cisco 形式。%s' % (why, sel, fix)


# ---------------------------------------------------------------- ポート
def _ports(M):
    p = M.page
    for it in p.items.values():
        if it.owner is None or it.kind not in ('port', 'portchannel'):
            continue
        dv = M.dev_by_uid[it.owner]
        if it.kind == 'portchannel':
            name, note, kind = it.text.split(' ')[0], '', 'po'
        else:
            name, note = X.split_port_name(it.text)
            kind = 'virtual' if re.match(r'^(Tun|Tu|Lo|Vl)', name, re.I) else 'port'
        key = name
        if key in dv.ports:
            if dv.is_nw:
                M.F.add('N-05', 'ERROR', '%s %s' % (dv.cfgname, name), '同じ機器に同じポート名が2つある',
                        basis='ポートの箱のラベルが重複', recommend='どちらかのポート名を直す',
                        provisional='2つ目を `%s#2` として扱う' % name, cells=[dv.ports[key].cell, it.id], diagram=name)
            key = name + '#2'
        pt = Port(dv, key, note, it, kind)
        dv.ports[key] = pt
        M.port_by_cell[it.id] = pt
    # Po のメンバー（Po 箱と重なるポート）
    for dv in M.devices:
        pos = [x for x in dv.ports.values() if x.kind == 'po']
        for po in pos:
            for pt in dv.ports.values():
                if pt.kind == 'port' and pt.po is None and _touch(po.item.rect, pt.item.rect):
                    po.members.append(pt)
                    pt.po = po
            po.members.sort(key=lambda x: _port_sort(x.name))


def _touch(a, b, tol=3):
    return not (a[0] + a[2] + tol < b[0] or b[0] + b[2] + tol < a[0] or
                a[1] + a[3] + tol < b[1] or b[1] + b[3] + tol < a[1])


def _port_sort(name):
    return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', name)]


# ---------------------------------------------------------------- セグメント台帳
def _segments(M):
    p = M.page
    lab_of = {}
    for sid, (lid, how, eid) in M.raw.seg_label.items():
        lab_of[sid] = (p.items[lid], how)
    for it in p.items.values():
        if it.kind != 'segment' or it.owner is None:
            continue
        dv = M.dev_by_uid[it.owner]
        key = (dv.site, it.color())
        sg = M.segments.get(key) or Segment(key)
        M.segments[key] = sg
        sg.items.append(it.id)
        if it.id in lab_of:
            lab, how = lab_of[it.id]
            sg.labels.append((X.parse_seglabel(lab.text), lab.id, how, dv))
        elif not dv.is_nw:
            pass
    # サーバーの中の横線は、サーバーをつなぐスイッチの拠点に入れ直す（_links 後に再計算）
    for sg in M.segments.values():
        _merge_labels(M, sg)


def _merge_labels(M, sg):
    labs = sg.labels
    nw_labs = [l for l in labs if l[3].is_nw] or labs
    names = Counter(norm_name(l[0]['name']) for l in nw_labs if l[0]['name'])
    vlans = Counter(l[0]['vlan'] for l in nw_labs if l[0]['vlan'])
    cidrs = Counter(l[0]['cidr'] for l in nw_labs if l[0]['cidr'])
    if names:
        best = names.most_common(1)[0][0]
        orig = [l[0]['name'] for l in nw_labs if norm_name(l[0]['name']) == best]
        sg.name = orig[0]
    if vlans:
        sg.vlan = vlans.most_common(1)[0][0]
        if len(vlans) > 1:
            M.F.add('V-02', 'WARN', '%s %s' % (sg.site, sg.name), '同じ色の横線に違う VLAN ID のラベルがある: %s' %
                    ', '.join('VLAN%s' % ('-'.join(map(str, set(v)))) for v in vlans),
                    basis='同じ拠点・同じ色の横線は同じセグメントとして扱う', recommend='ラベルの VLAN ID を揃える',
                    provisional='多い方の VLAN%s を採用' % sg.vlan_text(), cells=[l[1] for l in nw_labs])
    if cidrs:
        sg.cidr = cidrs.most_common(1)[0][0]
        if len(cidrs) > 1:
            M.F.add('A-01', 'ERROR', '%s %s' % (sg.site, sg.name), '同じセグメントのラベルに違うアドレスがある: %s' %
                    ', '.join(cidrs), basis='同じ拠点・同じ色の横線', recommend='ラベルのアドレスを揃える',
                    provisional='多い方の %s を採用' % sg.cidr, cells=[l[1] for l in nw_labs])
    if not sg.name and sg.vlan:
        sg.name = 'VLAN%s' % sg.vlan_text()


def _orphan_labels(M):
    """横線が無く IP バッジだけで作ったセグメント（SEG_色）に、バッジの近くにある未使用のラベルを付ける
    （例: FW の外側の「x.x.x.x / NGT-INET」）"""
    p = M.page
    used = {v[0] for v in M.raw.seg_label.values()}
    free = [it for it in p.items.values() if it.kind == 'seglabel' and it.id not in used and it.rect]
    for key, sg in M.segments.items():
        if sg.labels or not (sg.name or '').startswith('SEG_'):
            continue
        cells = [l3.badge_cell for d in M.devices for l3 in d.l3 if l3.segkey == key and l3.badge_cell]
        best = None
        for c in cells:
            b = p.items.get(c)
            if b is None or not b.rect:
                continue
            for lab in free:
                d = rect_gap(lab.rect, b.rect)
                if d <= 120 and (best is None or d < best[0]):
                    best = (d, lab, b)
        if best is None:
            continue
        d, lab, b = best
        pr = X.parse_seglabel(lab.text)
        sg.labels.append((pr, lab.id, 'near', None))
        sg.name = pr['name'] or sg.name
        sg.cidr = pr['cidr'] or sg.cidr
        sg.vlan = pr['vlan'] or sg.vlan
        used.add(lab.id)
        free.remove(lab)
        M.F.add('V-03', 'WARN', '%s %s' % (sg.site, sg.name), '横線が無く、IP バッジ（%s）の近くのラベル「%s」をセグメント名にした' % (
            b.text, lab.text), basis='バッジの色のセグメントにラベルが無い', recommend='横線を描き、ラベルを線でつなぐ',
            provisional='ラベル「%s」のセグメントとして設定' % lab.text, cells=[lab.id, b.id])


def seg_ident(M, key):
    """拠点間で共有する外部セグメント（VLAN なし・同名・同アドレス）は同じものとして扱う"""
    sg = M.segments.get(key)
    if sg is None:
        return key
    if not sg.vlan and sg.cidr:
        return ('*', norm_name(sg.name), sg.cidr)
    return key


def seg_for(M, site, color, create=True):
    key = (site, (color or '').upper())
    sg = M.segments.get(key)
    if sg is None and create and color:
        sg = Segment(key)
        sg.name = 'SEG_%s' % color.lstrip('#')
        M.segments[key] = sg
    return sg


# ---------------------------------------------------------------- 物理リンク
def _links(M):
    for e in M.raw.edges['physical']:
        _add_link(M, e['a'], e['b'], e)
    # サーバー・AP の拠点 = つながる NW 機器の拠点の多数派
    for dv in M.devices:
        if dv.is_nw:
            continue
        sites = Counter()
        for pt in dv.ports.values():
            for lk in pt.links:
                o = lk.other(pt)
                if o is not None and o.dev.is_nw:
                    sites[o.dev.site] += 1
        if sites:
            s = sites.most_common(1)[0][0]
            if s != dv.site:
                M.F.add('N-02', 'WARN', dv.cfgname, '%s 拠点の機器につながっているが、ホスト名の接頭辞が %s' % (s, dv.site),
                        basis='接続先の NW 機器の拠点（ホスト名の接頭辞）と違う',
                        recommend='ホスト名の拠点接頭辞を直す（コピー&ペーストの残りの可能性）',
                        provisional='%s 拠点の機器として扱う' % s, cells=[dv.label_id], diagram=dv.name)
                dv.site = s
    # 多重接続
    for dv in M.nw():
        for pt in dv.ports.values():
            if len(pt.links) > 1 and not pt.is_range and pt.kind == 'port':
                M.F.add('P-02', 'ERROR', '%s %s' % (dv.cfgname, pt.name), '1つの物理ポートに %d 本のケーブル' % len(pt.links),
                        recommend='接続先を確認し、ポートを分ける', provisional='すべての接続を description に併記',
                        cells=[l.edge for l in pt.links])


def _add_link(M, s, t, e, inferred=False):
    ps = M.port_by_cell.get(s.id) if s is not None else None
    pt = M.port_by_cell.get(t.id) if t is not None else None
    ms, mt = X.endpoint_mark(e['start']), X.endpoint_mark(e['end'])
    if ps is None and pt is None:
        return None
    if ps is None:
        ps, pt, ms, mt, s, t = pt, None, mt, ms, t, s
    ext = ''
    if pt is None and t is not None:
        ext = t.text or _near_text(M, t) or '外部機器'
    lk = Link(ps, pt, e['id'], e['width'], ms, mt, e['color'], inferred=inferred, ext_name=ext)
    ps.links.append(lk)
    if pt is not None:
        pt.links.append(lk)
    M.links.append(lk)
    return lk


def _near_text(M, it):
    best = None
    for o in M.page.items.values():
        if o.kind == 'text' and o.rect and it.rect:
            d = rect_gap(o.rect, it.rect)
            if d <= 30 and (best is None or d < best[0]):
                best = (d, o.text)
    return best[1] if best else ''


# ---------------------------------------------------------------- 所属（論理接続）
def _memberships(M):
    p = M.page
    for e in M.raw.edges['logical']:
        seg, oth = (e['a'], e['b']) if e['a'].kind == 'segment' else (e['b'], e['a'])
        if seg.owner is None:
            continue
        sdev = M.dev_by_uid[seg.owner]
        key = (sdev.site, seg.color())
        color_ok = not seg.color() or (e['color'] or '') == seg.color()
        if not color_ok:
            f = M.F.add('D-03', 'WARN', '%s %s' % (M.dev_by_uid[oth.owner].cfgname if oth.owner else '-', oth.text),
                        '所属線の色（%s）が接続先の横線の色（%s）と違う' % (e['color'] or '既定/黒', seg.color()),
                        basis='drawio の接続先（target/source）は %s の横線' % (M.segments.get(key).name if key in M.segments else seg.color()),
                        recommend='線の色か接続先を直す（コピー&ペーストの残りの可能性）',
                        provisional='接続先の横線を正として VLAN 所属を決めた', cells=[e['id']])
            _ref(M, f, oth)
        _attach(M, oth, key, 'edge', [e['id']], color_ok)
    for e in M.raw.edges['to_label']:
        lab, oth = (e['a'], e['b']) if e['a'].kind == 'seglabel' else (e['b'], e['a'])
        key = _label_seg(M, lab, oth)
        odev = M.dev_by_uid.get(oth.owner)
        f = M.F.add('D-04', 'WARN', '%s %s' % (odev.cfgname if odev else '-', oth.text),
                    '所属線が横線ではなくラベル「%s」につながっている' % lab.text,
                    basis='drawio の接続先がラベルのテキスト（cell %s）' % lab.id,
                    recommend='線の端を横線につなぎ直す',
                    provisional='ラベルが示すセグメント（%s）への所属として設定' % (M.segments[key].name if key else '不明'),
                    cells=[e['id'], lab.id])
        _ref(M, f, oth)
        if key:
            _attach(M, oth, key, 'label', [e['id']], True)
    for e in M.raw.edges['l3port']:
        rt, oth = (e['a'], e['b']) if e['a'].kind == 'routing' else (e['b'], e['a'])
        pt = M.port_by_cell.get(oth.id)
        if pt is None:
            continue
        pt.l3_routing = rt  # type: ignore[attr-defined]
        pt.l3_color = e['color']  # type: ignore[attr-defined]
        pt.l3_cells = [e['id']]  # type: ignore[attr-defined]


def _ref(M, f, it):
    pt = M.port_by_cell.get(it.id)
    if pt is not None:
        f.attach(pt.dev.cfgname, pt.name)
    elif it.owner and M.dev_by_uid.get(it.owner) is not None:
        f.attach(M.dev_by_uid[it.owner].cfgname, None)


def _label_seg(M, lab, oth):
    for sid, (lid, how, eid) in M.raw.seg_label.items():
        if lid == lab.id:
            it = M.page.items[sid]
            if it.owner:
                return (M.dev_by_uid[it.owner].site, it.color())
    pr = X.parse_seglabel(lab.text)
    odev = M.dev_by_uid.get(oth.owner)
    site = odev.site if odev else None
    for key, sg in M.segments.items():
        if (site is None or sg.site == site) and pr['vlan'] and sg.vlan == pr['vlan']:
            return key
    return None


def _attach(M, it, key, how, cells, color_ok=True):
    if it.kind == 'routing':
        dv = M.dev_by_uid.get(it.owner)
        if dv is None:
            return
        dv._l3memb = getattr(dv, '_l3memb', {})  # type: ignore[attr-defined]
        dv._l3memb.setdefault(key, (it, how, cells))
        return
    pt = M.port_by_cell.get(it.id)
    if pt is None:
        return
    if key not in pt.memb:
        pt.memb[key] = Membership(key, how, cells, color_ok)


# ---------------------------------------------------------------- 冗長ペア
def _pairs(M):
    nw = M.nw()
    linked = defaultdict(set)
    for lk in M.links:
        if lk.b is not None:
            linked[lk.a.dev.uid].add(lk.b.dev.uid)
            linked[lk.b.dev.uid].add(lk.a.dev.uid)
    for a in nw:
        if a.pair:
            continue
        cands = [b for b in nw if b is not a and b.pair is None and b.site == a.site and b.role == a.role
                 and stem(b.cfgname) == stem(a.cfgname) and b.uid in linked[a.uid]]
        if not cands:
            continue
        b = sorted(cands, key=lambda x: (num(x.cfgname), x.cfgname))[0]
        a.pair, b.pair = b, a
        first = sorted([a, b], key=lambda x: (num(x.cfgname), x.cfgname))
        first[0].primary, first[1].primary = True, False


def counterpart(M, pb):
    """ペアの相手機器で pb に対応するポート（結線の対称性 → 名前の順）"""
    B = pb.dev
    A = B.pair
    if A is None:
        return None, None
    target = pb.po if (pb.po is not None) else pb
    if pb.kind == 'po':
        for m in pb.members:
            pa, how = counterpart(M, m)
            if pa is not None and pa.po is not None:
                return pa.po, how
        pa = A.ports.get(pb.name)
        return pa, 'name'
    for lk in pb.links:
        q = lk.other(pb)
        if q is None:
            continue
        Q = q.dev
        if Q is A:
            pa = A.ports.get(pb.name)
            return pa, 'name'
        Qc = Q.pair or Q
        cands = []
        for pa in A.ports.values():
            for lk2 in pa.links:
                q2 = lk2.other(pa)
                if q2 is not None and q2.dev is Qc and (Qc is not Q or True):
                    cands.append((q2.name == q.name, pa.name == pb.name, pa))
        if cands:
            cands.sort(key=lambda x: (not x[0], not x[1], x[2].name))
            if Qc is not Q or cands[0][0] or cands[0][1]:
                return cands[0][2], 'link'
    pa = A.ports.get(pb.name)
    return pa, 'name' if pa else None


# ---------------------------------------------------------------- 未接続線（6.5）
def _dangling(M, phase):
    thr = float(M.project.get('dangling_distance'))
    for e in M.raw.edges['dangling']:
        end = e['a'] or e['b']
        is_link = end is not None and end.kind in ('port', 'portchannel')
        if (phase == 'link') != is_link:
            continue
        near = e.get('near')
        nitem = near['item'] if near and near['dist'] <= thr else None
        odev = M.dev_by_uid.get(end.owner) if end is not None else None
        where = '%s %s' % (odev.cfgname if odev else '-', end.text or '[%s]' % end.kind)
        fe = e.get('free_end')
        base = '線の片端が図形につながっていない（もう一端: %s、未接続端 (%d,%d)）' % (where, fe[0], fe[1]) if fe else \
            '線の片端が図形につながっていない（もう一端: %s）' % where
        ok, support, what = False, '', ''
        if end.kind == 'segment' and nitem is not None and nitem.kind in ('routing', 'port', 'portchannel', 'text'):
            key = (odev.site, end.color()) if odev else None
            ndev = M.dev_by_uid.get(nitem.owner)
            support = _support_seg(M, nitem, ndev, key)
            what = '%s %s と横線（%s）の所属線' % (ndev.cfgname if ndev else '-', nitem.text,
                                           M.segments[key].name if key in M.segments else end.color())
            if support and key:
                _attach(M, nitem, key, 'dangling', [e['id']])
                ok = True
        elif end.kind in ('port', 'portchannel') and nitem is not None and nitem.kind == 'port':
            pa = M.port_by_cell.get(end.id)
            pb = M.port_by_cell.get(nitem.id)
            if pa is not None and pb is not None and pa.dev is not pb.dev:
                support = _support_link(M, pa, pb)
                what = '%s %s と %s %s のケーブル' % (pa.dev.cfgname, pa.name, pb.dev.cfgname, pb.name)
                if support:
                    _add_link(M, end, nitem, e, inferred=True)
                    ok = True
        if ok:
            f = M.F.add('P-01', 'WARN', where, base + '。推定した接続先: %s' % what,
                        basis='未接続端が %s（cell %s）の上で終わっている（距離 %s）。裏付け: %s' % (
                            nitem.text or nitem.kind, nitem.id, near['dist'], support),
                        recommend='線の端を %s につなぎ直す' % (nitem.text or nitem.kind),
                        provisional='推定した接続として設定（6.5）', cells=[e['id'], nitem.id])
            _ref(M, f, nitem)
            if end is not None:
                _ref(M, f, end)
            M.guess(odev.cfgname if odev else '-', '未接続線 %s' % e['id'], what, f.basis)
        else:
            pa = M.port_by_cell.get(end.id) if end is not None else None
            prov = '設定には使わない'
            if pa is not None and pa.dev.is_nw:
                pa.shutdown_reason = '接続先不明（未接続線 %s）' % e['id']
                prov = 'ポートを shutdown（description に接続先不明）'
            sev = 'WARN' if (odev and odev.cls in ('nw', 'server')) else 'INFO'
            f = M.F.add('P-01', sev, where, base,
                    basis=('近くの要素: %s（距離 %s）。裏付けが無いので推定しない' % (nitem.text, near['dist']))
                    if nitem is not None else '近く（%gpx 以内）に接続先の候補が無い' % thr,
                    recommend='線の端を正しい図形につなぐか、不要なら削除する', provisional=prov,
                    cells=[e['id']] + ([nitem.id] if nitem is not None else []))
            if pa is not None:
                f.attach(pa.dev.cfgname, pa.name)


def _support_seg(M, nitem, ndev, key):
    if ndev is None or key is None:
        return ''
    color = key[1]
    if nitem.kind == 'routing':
        for b in ndev.badges or _badges_of(M, ndev):
            if b[1] == color:
                return '同じ機器に %s の IP バッジ（%s）がある' % (color, b[3])
        if ndev.pair is not None:
            for b in _badges_of(M, ndev.pair):
                if b[1] == color:
                    return '冗長ペアの %s に同じ色の IP バッジがある' % ndev.pair.cfgname
    pt = M.port_by_cell.get(nitem.id)
    if pt is not None:
        if ndev.pair is not None:
            pa, how = counterpart(M, pt)
            if pa is not None and any(k[1] == color for k in pa.eff_memb()):
                return '冗長ペアの %s %s が同じ色の横線に所属' % (pa.dev.cfgname, pa.name)
        for lk in pt.links:
            q = lk.other(pt)
            if q is not None and any(k[1] == color for k in q.eff_memb()):
                return '接続先の %s %s が同じ色のセグメントに所属' % (q.dev.cfgname, q.name)
    return ''


def _support_link(M, pa, pb):
    A = pa.dev
    if A.pair is not None:
        for p2 in A.pair.ports.values():
            for lk in p2.links:
                q = lk.other(p2)
                if q is not None and (q.dev is pb.dev or q.dev is pb.dev.pair):
                    return '冗長ペアの %s %s が %s %s に接続（同じ拠点のペアの対称性）' % (
                        A.pair.cfgname, p2.name, q.dev.cfgname, q.name)
    return ''


def _badges_of(M, dv):
    if dv.badges:
        return dv.badges
    for it in M.page.items.values():
        if it.kind == 'ipbadge' and it.owner == dv.uid:
            t = it.text
            host = None
            m = re.match(r'^\.?(\d{1,3})$', t)
            if m:
                host = int(m.group(1))
            dv.badges.append((it, it.color(), host, t))
    return dv.badges


# ---------------------------------------------------------------- 省略（対称性）
def _symmetry(M):
    for B in M.nw():
        A = B.pair
        if A is None:
            continue
        copied = []
        for pb in list(B.ports.values()):
            if pb.memb or (pb.po is not None and pb.po.memb) or pb.kind == 'virtual':
                continue
            if pb.po is not None:
                continue  # Po 単位で扱う
            pa, how = counterpart(M, pb)
            if pa is None:
                continue
            src = pa.memb if pa.kind == 'po' or pa.po is None else pa.po.memb
            if pb.kind == 'port' and pa.po is not None and pb.po is None:
                src = pa.po.memb
            if not src:
                continue
            for k, m in src.items():
                pb.memb[k] = Membership(k, 'symmetry', [], True, note='%s %s から' % (A.cfgname, pa.name))
            copied.append((pb, pa, how))
            if how == 'link' and pa.name != pb.name and pb.kind == 'port':
                _port_name_mismatch(M, pb, pa)
        # Po のメンバーが無い Po もコピー対象（上で Po 単位にコピー済み）
        if getattr(A, '_l3memb', None) and not getattr(B, '_l3memb', None) and B.routings:
            B._l3memb = {k: (B.routings[0], 'symmetry', []) for k, v in A._l3memb.items()}  # type: ignore
            copied.append(('L3', None, None))
        if copied:
            M.F.add('P-08', 'INFO', '%s ⇔ %s' % (A.cfgname, B.cfgname),
                    '%s の箱の中の横線・所属線が描かれていない（%d 箇所）' % (B.cfgname, len(copied)),
                    basis='冗長ペアの片方の省略（ナレッジ 2.10）',
                    recommend='省略でよければ対応不要。02号機だけ構成が違うなら図に描く',
                    provisional='%s と同じ所属と推定（【推測：対称性】）。ポートの対応は結線の対称性→ポート名の順で決めた' % A.cfgname,
                    cells=[B.box_id])
            M.guess(B.cfgname, 'VLAN 所属・L3 の対称コピー', '%s と同じ' % A.cfgname, '冗長ペアの片方の省略（2.10）')


def _port_name_mismatch(M, pb, pa):
    speed = ''
    for lk in pb.links:
        if X.width_class(lk.width) == 'thick' and pb.name.lower().startswith('gi'):
            speed = '。1G のポート名だが太線（10G 系のケーブル）で接続されている'
    f = M.F.add('P-03', 'WARN', '%s %s' % (pb.dev.cfgname, pb.name),
            '冗長ペアの %s では同じ位置の接続が %s なのに、%s になっている%s' % (pa.dev.cfgname, pa.name, pb.name, speed),
            basis='結線の対称性（同じ拠点の冗長ペアの対向）',
            recommend='誤記なら図のポート名を %s に直す' % pa.name,
            provisional='ポート名は図のまま %s で出力し、所属は %s と同じにした（D8）' % (pb.name, pa.name),
            cells=[pb.cell, pa.cell], diagram=pb.name)
    f.attach(pb.dev.cfgname, pb.name)
    pb.name_warn = pa.name  # type: ignore[attr-defined]


# ---------------------------------------------------------------- サーバー側から（R16）
def _server_side(M):
    """スイッチ側に所属線が無いサーバー接続ポートは、サーバー内の NIC の所属から決める"""
    for lk in M.links:
        for p_sw, p_sv in ((lk.a, lk.b), (lk.b, lk.a)):
            if p_sw is None or p_sv is None or not p_sw.dev.is_nw or p_sv.dev.cls != 'server':
                continue
            if p_sw.eff_memb():
                continue
            nic = p_sv.memb
            if not nic:
                continue
            for k in nic:
                key = (p_sw.dev.site, k[1])
                if key in M.segments:
                    p_sw.memb[key] = Membership(key, 'server', [], True, note='%s %s の所属から' % (p_sv.dev.cfgname, p_sv.name))
            M.guess(p_sw.dev.cfgname, '%s の VLAN' % p_sw.name, '/'.join(M.segments[k].name for k in p_sw.memb),
                    'スイッチ側に所属線が無いため、サーバー %s の NIC の所属から決めた（R16）' % p_sv.dev.cfgname)


# ---------------------------------------------------------------- L3
def _l3(M):
    for dv in M.nw():
        badges = _badges_of(M, dv)
        lm = dict(getattr(dv, '_l3memb', {}))
        rt_default = None
        for r in dv.routings:
            if r.text == 'GRT':
                rt_default = r
        # バッジの色で L3 を補う（ルーティング箱があり、線が無い場合）
        for b in badges:
            key = (dv.site, b[1])
            if key in lm:
                continue
            if dv.routings and (dv.role in ('l3sw', 'router', 'fw')):
                if key in M.segments and _is_port_l3(dv, b[1]) is None:
                    lm[key] = (rt_default or dv.routings[0], 'badge', [b[0].id])
        for key, (rt, how, cells) in sorted(lm.items(), key=lambda kv: _seg_sort(M, kv[0])):
            vrf = _vrf_name(rt)
            l3 = L3If(dv, key, vrf, how, cells)
            _set_host(M, l3, dv, key[1])
            dv.l3.append(l3)
        # ポートとルーティング箱の直結（L3 ポート、管理 VRF）
        for pt in dv.ports.values():
            rt = getattr(pt, 'l3_routing', None)
            if rt is None:
                continue
            color = getattr(pt, 'l3_color', '') or ''
            key = (dv.site, color.upper()) if color else None
            vrf = _vrf_name(rt)
            if pt.name.lower().startswith('mgmt') or (vrf and vrf.lower().startswith('mgmt')):
                dv.mgmt = dict(kind='oob', port=pt, vrf=vrf or M.project.get('mgmt_vrf_name'), segkey=key,
                               cells=getattr(pt, 'l3_cells', []))
                l3 = L3If(dv, key, dv.mgmt['vrf'], 'edge', getattr(pt, 'l3_cells', []))
                l3.kind = 'mgmt'
                l3.port = pt
                _set_host(M, l3, dv, color.upper())
                dv.mgmt['l3'] = l3
                pt.l3 = l3
            else:
                seg_for(M, dv.site, color)
                l3 = L3If(dv, key, vrf, 'edge', getattr(pt, 'l3_cells', []))
                l3.kind = 'phys'
                l3.port = pt
                _set_host(M, l3, dv, color.upper())
                pt.l3 = l3
                dv.l3.append(l3)
        _l3_kinds(M, dv)
        _mgmt(M, dv)


def _seg_sort(M, key):
    sg = M.segments.get(key)
    return (sg.vlan[0] if sg and sg.vlan else 99999, sg.name if sg else '', key[1])


def _vrf_name(rt):
    if rt is None or rt.text == 'GRT':
        return None
    t = rt.text
    m = re.match(r'^vrf\s*(?:/\s*)?(.+)$', t, re.I)
    if m:
        return m.group(1).strip(' ()')
    m = re.match(r'^VRF\s*\((.+)\)$', t)
    if m:
        return m.group(1)
    return t


def _is_port_l3(dv, color):
    for pt in dv.ports.values():
        if (getattr(pt, 'l3_color', '') or '').upper() == color:
            return pt
    return None


def _set_host(M, l3, dv, color):
    for b in _badges_of(M, dv):
        if b[1] == color:
            l3.badge_text = b[3]
            l3.badge_cell = b[0].id
            l3.host = b[2]
            if b[2] is not None and not b[3].startswith('.'):
                M.F.add('A-06', 'INFO', '%s %s' % (dv.cfgname, b[3]), 'IP バッジにドットが無い（「%s」）' % b[3],
                        basis='バッジは第4オクテットを「.N」で書く規約', recommend='「.%s」に直す' % b[3],
                        provisional='.%s として採用' % b[3], cells=[b[0].id], diagram=b[3])
            return
    l3.badge_text = None


def _l3_kinds(M, dv):
    """FW/RT: 同一セグメントに2ポート以上→ BVI / スイッチポート＋SVI。1ポート→ L3 物理IF"""
    if dv.role not in ('fw', 'router'):
        return
    for l3 in dv.l3:
        if l3.kind in ('mgmt',) or l3.port is not None:
            continue
        ports = [pt for pt in dv.ports.values() if l3.segkey in pt.memb and pt.po is None]
        sg = M.segments.get(l3.segkey)
        if len(ports) >= 2:
            l3.kind = 'bvi' if dv.role == 'fw' else 'svi'
            l3.members = sorted(ports, key=lambda x: _port_sort(x.name))
        elif len(ports) == 1:
            l3.kind = 'phys'
            l3.port = ports[0]
            ports[0].l3 = l3
        else:
            l3.kind = 'svi' if (sg and sg.vlan) else 'phys'


def _mgmt(M, dv):
    if dv.mgmt is not None:
        return
    # vrf 箱（mgmt）と Mgmt ポートがあるが、線が省略されている（冗長ペアの片方など）
    vrfbox = [r for r in dv.routings if (_vrf_name(r) or '').lower().startswith('mgmt')]
    mport = [pt for pt in dv.ports.values() if pt.name.lower().startswith('mgmt') and pt.l3 is None]
    if vrfbox and mport:
        pt = mport[0]
        key = None
        for b in _badges_of(M, dv):
            if (dv.site, b[1]) in M.segments:
                key = (dv.site, b[1])
        l3 = L3If(dv, key, _vrf_name(vrfbox[0]), 'symmetry', [vrfbox[0].id])
        l3.kind = 'mgmt'
        l3.port = pt
        if key:
            _set_host(M, l3, dv, key[1])
        pt.l3 = l3
        dv.mgmt = dict(kind='oob', port=pt, vrf=l3.vrf, segkey=key, l3=l3, cells=[vrfbox[0].id])
        M.guess(dv.cfgname, '%s を vrf %s に入れる' % (pt.name, l3.vrf), '', 'vrf 箱と Mgmt ポートの間の線が無い（省略と推定）')
        return
    # L2SW: 管理セグメント上のバッジ（ルーティング箱なし）→ インバンド SVI
    if not dv.routings:
        for b in _badges_of(M, dv):
            key = (dv.site, b[1])
            sg = M.segments.get(key)
            carried = any(key in pt.eff_memb() for pt in dv.ports.values()) or \
                any(it_c == b[1] for it_c in [M.page.items[i].color() for i in [x.id for x in dv.seg_items]])
            if sg is not None and carried:
                l3 = L3If(dv, key, None, 'badge', [b[0].id])
                l3.kind = 'svi'
                l3.host = b[2]
                l3.badge_text = b[3]
                l3.badge_cell = b[0].id
                dv.mgmt = dict(kind='inband', l3=l3, segkey=key, cells=[b[0].id])
                dv.l3.append(l3)
                return
    # R12: Mgmt ポートが管理SWにつながるが、vrf 箱もバッジも無い
    for pt in dv.ports.values():
        if pt.name.lower().startswith('mgmt') and pt.l3 is None and pt.links:
            q = pt.links[0].other(pt)
            key = None
            if q is not None:
                mm = list(q.eff_memb())
                if len(mm) == 1:
                    key = mm[0]
            vrf = M.project.get('mgmt_vrf_name')
            M.project.note_default('mgmt_vrf_name', [dv.cfgname])
            l3 = L3If(dv, key, vrf, 'r12', [pt.cell])
            l3.kind = 'mgmt'
            l3.port = pt
            pt.l3 = l3
            dv.mgmt = dict(kind='r12', port=pt, vrf=vrf, segkey=key, l3=l3, cells=[pt.cell])
            M.guess(dv.cfgname, '%s を管理 VRF %s に入れる' % (pt.name, vrf), 'IP は <TBD>',
                    'Mgmt ポートが管理SWにつながるが vrf 箱もバッジも無い（R12）')
            return


# ---------------------------------------------------------------- VRRP
def _vrrp(M):
    p = M.page
    pairs = [(a, a.pair) for a in M.nw() if a.pair is not None and a.primary and a.routings and a.pair.routings]
    vips = [it for it in p.items.values() if it.kind == 'vip']
    for a, b in pairs:
        ux0 = min(a.box[0], b.box[0])
        uy0 = min(a.box[1], b.box[1])
        ux1 = max(a.box[0] + a.box[2], b.box[0] + b.box[2])
        uy1 = max(a.box[1] + a.box[3], b.box[1] + b.box[3])
        mine = []
        for v in vips:
            cx, cy = v.center()
            if ux0 <= cx <= ux1 and uy0 <= cy <= uy1:
                mine.append(v)
        common = [k for k in (x.segkey for x in a.l3 if x.kind == 'svi') if k in {x.segkey for x in b.l3}]
        assigned = {}
        for v in mine:
            m = re.search(r'\.(\d+|[a-z](?:\+\d+)?)', v.text)
            host = int(m.group(1)) if m and m.group(1).isdigit() else None
            col = v.color()
            if (a.site, col) in M.segments and col not in GRAY:
                assigned[(a.site, col)] = (host, v)
        for v in mine:
            col = v.color()
            m = re.search(r'\.(\d+)', v.text)
            host = int(m.group(1)) if m else None
            if (a.site, col) in M.segments and col not in GRAY:
                continue
            for k in common:
                assigned.setdefault(k, (host, v))
        for k, (host, v) in assigned.items():
            sg = M.segments.get(k)
            for dv in (a, b):
                for l3 in dv.l3:
                    if l3.segkey == k and l3.kind == 'svi':
                        l3.vip = host
                        l3.vip_cell = v.id
            if sg is not None:
                sg.vip = host
                sg.vip_cell = v.id
        for k in common:
            if k not in assigned:
                sg = M.segments.get(k)
                M.F.add('L-02', 'INFO', '%s ⇔ %s %s' % (a.cfgname, b.cfgname, sg.name if sg else k),
                        '両方の機器に L3 があるが VIP の記載が無い', recommend='VIP を描くか、冗長化しないなら片方の L3 を外す',
                        provisional='VRRP を設定しない', cells=[a.box_id, b.box_id])


# ---------------------------------------------------------------- アドレス
def _site_blocks(M):
    for site in sorted({s.site for s in M.segments.values()}):
        spec = M.project.sites.get(site, {})
        if spec.get('block'):
            M.site_block[site] = (ipaddress.ip_network(spec['block']), '【指定】')
        if spec.get('name'):
            M.site_names[spec['name']] = site
    cnt = defaultdict(Counter)
    for sg in M.segments.values():
        if sg.cidr and sg.vlan:
            try:
                n = ipaddress.ip_network(sg.cidr, strict=False)
            except ValueError:
                continue
            cnt[sg.site][n.supernet(new_prefix=16) if n.prefixlen >= 16 else n] += 1
    for site, c in cnt.items():
        if site in M.site_block:
            continue
        blk, k = c.most_common(1)[0]
        M.site_block[site] = (blk, '【推測】')
        M.guess(site, '拠点ブロック', str(blk), '拠点内のセグメント（VLAN あり）の多くが含まれる /16（%d 件）' % k)


def _addresses(M):
    _site_blocks(M)
    segs = [s for s in M.segments.values() if s.cidr]
    nets = {}
    for s in segs:
        try:
            nets[s.key] = ipaddress.ip_network(s.cidr, strict=False)
        except ValueError:
            M.F.add('A-03', 'ERROR', '%s %s' % (s.site, s.name), 'アドレス表記が不正: %s' % s.cidr, cells=s.items)
    suspect = defaultdict(list)
    for s in segs:
        if s.key not in nets or not s.vlan:
            continue
        blk = M.site_block.get(s.site)
        if blk and not nets[s.key].subnet_of(blk[0]) if nets[s.key].version == blk[0].version else False:
            suspect[s.key].append('拠点ブロック %s の外' % blk[0])
            M.F.add('A-02', 'WARN', '%s %s' % (s.site, s.name), '%s が拠点ブロック %s%s の外にある' % (s.cidr, blk[0], blk[1]),
                    basis='拠点内の他のセグメントのアドレス', recommend='ラベルのアドレスを確認する（他拠点の値のコピーの可能性）',
                    provisional='下の A-01/A-07 の扱いに従う', cells=[l[1] for l in s.labels])
    # 拠点間のラベル使い回し（A-07）
    bytext = defaultdict(list)
    for s in segs:
        for l in s.labels:
            if l[0]['cidr']:
                bytext[l[0]['text'].replace(' ', '')].append(s)
    for t, ss in bytext.items():
        sites = {s.site for s in ss}
        if len(sites) > 1 and any(s.vlan for s in ss):
            for s in ss:
                suspect[s.key].append('同じラベルが他拠点にもある')
            M.F.add('A-07', 'ERROR', t, '同じアドレスのラベル「%s」が複数の拠点（%s）にある' % (t, ', '.join(sorted(sites))),
                    basis='拠点ごとにアドレス帯が違うはず', recommend='どちらかの拠点のラベルを正しいアドレスに直す',
                    provisional='A-01 の扱いに従う', cells=[l[1] for s in ss for l in s.labels if l[0]['cidr']])
    # 重複・包含（A-01）
    keys = sorted(nets, key=lambda k: (k[0], str(nets[k])))
    conflicts = defaultdict(list)
    for i, k1 in enumerate(keys):
        for k2 in keys[i + 1:]:
            n1, n2 = nets[k1], nets[k2]
            if n1.version == n2.version and n1.overlaps(n2):
                s1, s2 = M.segments[k1], M.segments[k2]
                if n1 == n2 and not s1.vlan and not s2.vlan and norm_name(s1.name) == norm_name(s2.name):
                    continue  # 拠点間で共有する外部セグメント（拠点間接続など）
                conflicts[k1].append(k2)
                conflicts[k2].append(k1)
                rel = '同じ' if n1 == n2 else '包含関係'
                f = M.F.add('A-01', 'ERROR', '%s %s ⇔ %s %s' % (s1.site, s1.name, s2.site, s2.name),
                            'アドレスが%s（%s と %s）' % (rel, s1.cidr, s2.cidr),
                            basis='同じルーティングドメインでサブネットは重複できない',
                            recommend='どちらかのラベルを正しいアドレスに直す',
                            cells=[l[1] for l in s1.labels + s2.labels if l[0]['cidr']])
                f._segs = (k1, k2)  # type: ignore[attr-defined]
    # 解決: 補助ページ（論理構成図）→ 疑わしい方を TBD
    for f in M.F.by_check('A-01'):
        if not hasattr(f, '_segs'):
            continue
        res = []
        if not nets[f._segs[0]].overlaps(nets[f._segs[1]]):
            f.provisional = '別の指摘の解決で重複が解消（%s / %s）' % tuple(
                '%s %s=%s%s' % (M.segments[k].site, M.segments[k].name, M.segments[k].cidr, M.segments[k].cidr_src) for k in f._segs)
            continue
        for k in f._segs:
            s = M.segments[k]
            av = _aux_cidr(M, s)
            if av and av != s.cidr and not _overlaps_any(M, av, k, nets):
                res.append('%s %s は論理構成図の %s を採用【論】' % (s.site, s.name, av))
                s.cidr, s.cidr_src = av, '【論】'
                nets[k] = ipaddress.ip_network(av, strict=False)
        if not res:
            for k in f._segs:
                s = M.segments[k]
                if suspect.get(k) and not s.cidr_tbd:
                    s.cidr_tbd = True
                    res.append('%s %s を <TBD>（%s）' % (s.site, s.name, '、'.join(sorted(set(suspect[k])))))
            if not res:
                for k in f._segs:
                    M.segments[k].cidr_tbd = True
                res.append('どちらが正しいか決められないので両方 <TBD>')
        f.provisional = '；'.join(res)
    # 未解決のまま残った疑わしいセグメント（A-02/A-07 だけ）
    for k, why in suspect.items():
        s = M.segments[k]
        if s.cidr_src == '【図】' and not s.cidr_tbd:
            av = _aux_cidr(M, s)
            if av and av != s.cidr:
                s.cidr, s.cidr_src = av, '【論】'
            else:
                s.cidr_tbd = True
    # バッジの IP の妥当性（A-03）と重複（A-04）
    used = defaultdict(list)
    for dv in M.nw():
        for l3 in dv.l3:
            sg = M.segments.get(l3.segkey) if l3.segkey else None
            if sg is None or not sg.cidr or sg.cidr_tbd or sg.aggregate or l3.host is None:
                continue
            n = ipaddress.ip_network(sg.cidr, strict=False)
            if l3.host >= n.num_addresses - 1 or l3.host == 0:
                M.F.add('A-03', 'ERROR', '%s %s' % (dv.cfgname, sg.name),
                        'バッジ .%d が %s のネットワーク/ブロードキャストかサブネット外' % (l3.host, sg.cidr),
                        cells=[l3.badge_cell], provisional='IP を <TBD> にした')
                l3.host = None
                continue
            used[(l3.segkey, l3.host)].append((dv, l3.badge_cell))
            if l3.vip is not None:
                used[(l3.segkey, l3.vip, 'vip')].append((dv, l3.vip_cell))
    for k, l in used.items():
        if len(k) == 2 and len(l) > 1:
            sg = M.segments[k[0]]
            M.F.add('A-04', 'ERROR', '%s .%d' % (sg.name, k[1]), '同じセグメントで同じ IP（.%d）を持つ機器: %s' % (
                k[1], ', '.join(d.cfgname for d, c in l)), cells=[c for d, c in l])
    for (k, h, *_), l in list(used.items()):
        pass


def _overlaps_any(M, cidr, me, nets):
    n = ipaddress.ip_network(cidr, strict=False)
    return any(n.overlaps(v) for k, v in nets.items() if k != me and v.version == n.version)


def _aux_cidr(M, s):
    if not M.aux:
        return None
    blk = M.site_block.get(s.site)
    for a in M.aux.segments:
        if a['vlan'] == s.vlan and norm_name(a['name'])[:4] == norm_name(s.name)[:4] and a['cidr']:
            n = ipaddress.ip_network(a['cidr'], strict=False)
            if blk is None or (n.version == blk[0].version and n.subnet_of(blk[0])):
                return a['cidr']
    return None


# ---------------------------------------------------------------- 集約 VLAN（5.4、D10）
UNIT_RE = re.compile(r'([^\s、,。/]+?)ごとに')


def _aggregates(M):
    aggs = [s for s in M.segments.values() if s.aggregate]
    notes = []
    for it in M.raw.notes:
        if 'ごとに' in it.text:
            notes.append(('main', it.text, it))
    if M.aux:
        for n in M.aux.notes:
            notes.append(('aux', n['text'], n))
    for sg in aggs:
        spec = M.project.aggregates.get(sg.name) or M.project.aggregates.get(norm_name(sg.name)) or {}
        if spec.get('unit'):
            if spec['unit'] != 'none':
                sg.unit = dict(text=spec['unit'], source='【指定】', cell=None, devices=spec.get('unit_devices'))
            continue
        for src, text, it in notes:
            m = UNIT_RE.search(text)
            if not m:
                continue
            hit = False
            vl = X.VLAN_RE.search(text)
            if vl and sg.vlan and vl.group(1).replace(' ', '') == sg.vlan_text():
                hit = True
            elif src == 'main' and it.owner is None:
                pass
            elif src == 'aux' and it.get('segment') and norm_name(it['segment']['name'])[:4] == norm_name(sg.name)[:4] \
                    and it['segment']['vlan'] == sg.vlan:
                hit = True
            if hit:
                sg.unit = dict(text=m.group(1), source='【図注記】' if src == 'main' else '【論】',
                               cell=it.id if src == 'main' else it.get('id'), note=text)
                break
    # 単位の機器: その集約セグメントと、自分の管理用セグメントにだけ所属する L2SW
    for sg in aggs:
        if sg.unit is None:
            continue
        pats = sg.unit.get('devices')
        units = []
        for dv in M.nw():
            if pats:
                import fnmatch
                if any(fnmatch.fnmatch(dv.cfgname, p) for p in pats):
                    units.append(dv)
                continue
            if dv.role != 'l2sw':
                continue
            keys = set()
            for pt in dv.ports.values():
                keys.update(pt.eff_memb())
            mg = {dv.mgmt['segkey']} if dv.mgmt and dv.mgmt.get('segkey') else set()
            if sg.key in keys and keys <= {sg.key} | mg:
                units.append(dv)
        sg.unit['unit_devs'] = units
        # 同じ単位のグループ（リンクでつながる単位の機器）
        group = {}
        for dv in units:
            if dv.uid in group:
                continue
            comp = [dv]
            stack = [dv]
            while stack:
                x = stack.pop()
                for pt in x.ports.values():
                    for lk in pt.links:
                        o = lk.other(pt)
                        if o is not None and o.dev in units and o.dev not in comp:
                            comp.append(o.dev)
                            stack.append(o.dev)
            head = sorted(comp, key=lambda d: (num(d.cfgname), d.cfgname))[0]
            for x in comp:
                group[x.uid] = head
        sg.unit['group'] = group
    for sg in aggs:
        if sg.unit is None:
            M.F.add('V-05', 'INFO', '%s %s VLAN%s' % (sg.site, sg.name, sg.vlan_text()),
                    '集約表現の VLAN の払い出し単位（注記）が見つからない',
                    recommend='「フロアごとに1VLAN」などの注記か、既定値ファイルの aggregates で単位を指定する',
                    provisional='図の線のとおり範囲のまま設定。単位ごとの絞り込みを確認してください（5.4）', cells=sg.items[:1])


def unit_token(M, sg, dv):
    """集約 VLAN の、単位の機器向けのプレースホルダ"""
    head = sg.unit['group'].get(dv.uid) if sg.unit else None
    if head is None:
        return None
    return '<TBD:%s_VLAN@%s>' % (sg.name, head.cfgname)
