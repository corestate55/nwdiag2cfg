"""図形の分類（機器・ポート・横線・ラベル・バッジ・ルーティング箱・vip）と線の分類。

既存の tools/drawio_nwdiag_extract.py のロジックを移植し、次を足したもの。
- 回転した図形（Po 箱など）の座標補正（drawio.Page）
- ポートとルーティング箱を直接結ぶ線（L3 ポート、vrf の管理ポート）
- 線でつながっていないラベルと横線の近接による対応付け（V-03 で指摘）
- 凡例（線幅・端点記号 → コネクタ/ケーブル）の読み取り
- 注記テキストの収集
"""
import re

from .drawio import rect_dist, rect_gap, overlap, center_in

PORT_RE = re.compile(r'^(Te|Tw|Fo|Hu|Gi|Fa|Eth|Et|xe|ge|et|mgmt|Mgmt|MGMT|BMC|eth|ens|eno|bond|Po|ae|lag|Vl|vlan|Lo|'
                     r'Tun|Tu|wan|lan|port|nic)[\w/\-\.:]*', re.I)
PO_RE = re.compile(r'^((Po|Port-channel|ae|lag|bond)\d+|LAG)$', re.I)
IP_BADGE_RE = re.compile(r'^(\.?\d{1,3}(-\d{1,3})?|\.[a-z](\+\d+)?|\d{1,3}(\.\d{1,3}){3}(/\d+)?)$', re.I)
CIDR_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})')
# アドレス未定のラベル（x.x.x.x / NGT-INET など）
ADDR_PLACEHOLDER_RE = re.compile(r'(?<![\w.])(?:[xX\d]{1,3}\.){3}[xX]{1,3}(?:/[\dxX]{1,2})?(?![\w.])')
VLAN_RE = re.compile(r'VLAN\s*(\d+(?:\s*-\s*\d+)?)', re.I)
HOSTNAME_RE = re.compile(r'^[a-z][a-z0-9]*(-[a-z0-9]+)*-[a-z]+[a-z0-9]*\d+([A-Z].*)?$', re.I)
PORTNAME_SPLIT = re.compile(r'^((?:Te|Tw|Fo|Hu|Gi|Fa|Eth|Et|xe|ge|et|Po|Lo|Tun|Tu|Vl)[A-Za-z]*\s*[\d/\.:x]+(?:-\d+)?'
                            r'|Mgmt\d*|mgmt\d*|MGMT|BMC|eth\d+|ens\d+|eno\d+|bond\d+|wan\d*|lan\d*|port\d+)(.*)$')

LABEL_NEAR = 60  # 線でつながらないラベルを横線に対応付ける距離（px）


class Raw:
    """1ページ分の分類結果"""

    def __init__(self, page):
        self.page = page
        self.devices = []       # dict(uid, name, model, label_id, box, box_id)
        self.edges = {}         # category -> [edge dict]
        self.legend = {}        # (width_class, mark) -> dict(connector, cable)
        self.legend_texts = []  # 凡例中の文字（VRRP/HSRP の判定用）
        self.notes = []         # 注記（機器外・機器内の長い文）
        self.seg_label = {}     # segment id -> (label id, how)  how=edge|near
        self.frames = []        # (text, rect) ラック・フロアなどの枠名


def _classify_kind(page, it, devices):
    t = it.text
    r = it.rect
    if it.edge:
        return 'edge'
    if r is None:
        return 'edgelabel'
    if any(d['label_id'] == it.id for d in devices):
        return 'hostlabel'
    if any(d['box_id'] == it.id for d in devices):
        return 'devicebox'
    if t == 'GRT' or re.match(r'^vrf\b', t, re.I) or re.match(r'^VRF\s*\(', t):
        return 'routing'
    if PO_RE.match(t):
        return 'portchannel'
    if CIDR_RE.search(t) or (VLAN_RE.search(t) and len(t) < 80) or (ADDR_PLACEHOLDER_RE.search(t) and len(t) < 60):
        return 'seglabel'
    if PORT_RE.match(t) and r[2] <= 140 and r[3] <= 60:
        return 'port'
    if re.match(r'^vip\b', t, re.I):
        return 'vip'
    if IP_BADGE_RE.match(t) and it.color():
        return 'ipbadge'
    if not t and r[3] <= 14 and r[2] >= 40 and it.color():
        return 'segment'
    if t:
        return 'text'
    return 'shape'


def classify(page):
    raw = Raw(page)
    V = [it for it in page.items.values() if it.vertex and it.rect]
    hosts = [it for it in V if it.text and HOSTNAME_RE.match(it.text.split(' ')[0])
             and not CIDR_RE.search(it.text) and not VLAN_RE.search(it.text) and not PORT_RE.match(it.text)]
    for h in hosts:
        best = None
        for v in V:
            if v is h or v.text:
                continue
            x, y, w, hh = v.rect
            if w < 120 or hh < 80 or 'text' in v.style:
                continue
            if overlap(h.rect, v.rect):
                if best is None or w * hh < best.rect[2] * best.rect[3]:
                    best = v
        parts = [s.strip() for s in re.split(r' / ', h.text) if s.strip()]
        first = parts[0]
        # 「os1-core01C社 L3switch 9000-24」のような改行欠落: ホスト名の末尾の数字の直後で切る
        m = re.match(r'^([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*?-[A-Za-z]+[A-Za-z0-9]*?\d+)(?=[^a-z0-9\-]|$)(.*)$', first)
        if m:
            name, rest = m.group(1), m.group(2).strip()
        else:
            name, rest = first.split(' ')[0], ' '.join(first.split(' ')[1:])
        model = ' '.join(([rest] if rest else []) + parts[1:])
        raw.devices.append(dict(name=name, uid=name, model=model.strip().lstrip('/／:：-– ').strip(), label_id=h.id,
                                box=best.rect if best else None, box_id=best.id if best else None))
    seen = {}
    for d in raw.devices:
        seen[d['name']] = seen.get(d['name'], 0) + 1
        d['dup_index'] = seen[d['name']]
        if d['dup_index'] > 1:
            d['uid'] = '%s#%d' % (d['name'], d['dup_index'])

    def owner(it):
        if it.rect is None:
            return None
        c = [d for d in raw.devices if d['box'] and center_in(it.rect, d['box']) and it.id != d['box_id']]
        if not c:
            return None
        return min(c, key=lambda d: d['box'][2] * d['box'][3])

    for it in page.items.values():
        it.kind = _classify_kind(page, it, raw.devices)
        o = owner(it) if it.rect else None
        it.owner = o['uid'] if o else None
        it._dev = o  # type: ignore[attr-defined]
    return raw


def _ep(page, iid):
    return page.items.get(iid) if iid else None


def classify_edges(raw):
    p = raw.page
    cats = {k: [] for k in ('physical', 'logical', 'seglabel', 'l3port', 'pair', 'to_label', 'dangling', 'free',
                            'other', 'route')}
    for it in p.items.values():
        if not it.edge:
            continue
        s, t = _ep(p, it.source), _ep(p, it.target)
        st = it.style
        e = dict(id=it.id, a=s, b=t, color=it.stroke() or it.color(), width=st.get('strokeWidth', '1') or '1',
                 start=(st.get('startArrow', 'none'), st.get('startFill', '1')),
                 end=(st.get('endArrow', 'classic'), st.get('endFill', '1')),
                 dashed=st.get('dashed') == '1', labels=list(it.labels), item=it)
        ks = {x.kind for x in (s, t) if x is not None}
        if (s is None) and (t is None):
            cats['free'].append(e)
            continue
        if s is None or t is None:
            which = 'sourcePoint' if s is None else 'targetPoint'
            e['free_end'] = p.edge_point(it, which)
            e['near'] = nearest(p, e['free_end'], exclude=(s or t))
            cats['dangling'].append(e)
            continue
        if e['dashed'] and st.get('endArrow', 'classic') not in ('none', 'oval', ''):
            cats['route'].append(e)
            continue
        if 'seglabel' in ks and ks & {'port', 'portchannel', 'routing', 'ipbadge', 'text'} and 'segment' not in ks:
            cats['to_label'].append(e)
        elif 'segment' in ks and 'seglabel' in ks:
            cats['seglabel'].append(e)
        elif 'segment' in ks and ks - {'segment'}:
            cats['logical'].append(e)
        elif ks == {'routing'}:
            cats['pair'].append(e)
        elif 'routing' in ks and ks & {'port', 'portchannel', 'text'}:
            cats['l3port'].append(e)
        elif ks <= {'port', 'shape', 'text', 'portchannel', 'devicebox'} and s.owner != t.owner:
            cats['physical'].append(e)
        else:
            cats['other'].append(e)
    raw.edges = cats
    return raw


def nearest(page, pt, exclude=None, limit=60, kinds=('port', 'portchannel', 'segment', 'routing', 'seglabel', 'text')):
    if pt is None:
        return None
    best = None
    for it in page.items.values():
        if it is exclude or not it.rect or it.kind not in kinds:
            continue
        d = rect_dist(it.rect, pt)
        if d <= limit and (best is None or d < best[0]):
            best = (d, it)
    if not best:
        return None
    return dict(item=best[1], dist=round(best[0], 1))


def associate_labels(raw):
    """横線 → ラベル。線でつながっていれば edge、無ければ近接（near）。"""
    p = raw.page
    for e in raw.edges['seglabel']:
        seg, lab = (e['a'], e['b']) if e['a'].kind == 'segment' else (e['b'], e['a'])
        raw.seg_label.setdefault(seg.id, (lab.id, 'edge', e['id']))
    used = {v[0] for v in raw.seg_label.values()}
    to_label = {e['a'].id if e['a'].kind == 'seglabel' else e['b'].id for e in raw.edges['to_label']}
    segs = [it for it in p.items.values() if it.kind == 'segment']
    labels = [it for it in p.items.values() if it.kind == 'seglabel' and it.id not in used]
    pairs = []
    for lab in labels:
        for s in segs:
            if s.id in raw.seg_label:
                continue
            if lab.owner is not None and s.owner is not None and lab.owner != s.owner:
                continue
            d = rect_gap(lab.rect, s.rect)
            if d <= LABEL_NEAR:
                pairs.append((d, lab, s))
    pairs.sort(key=lambda x: (x[0], x[1].id, x[2].id))
    done_l, done_s = set(), set()
    for d, lab, s in pairs:
        if lab.id in done_l or s.id in done_s:
            continue
        # ラベルへ所属線がつながっている（D-04）ラベルは、所属の対象として残すだけで横線には付けない
        raw.seg_label[s.id] = (lab.id, 'near', None)
        done_l.add(lab.id)
        done_s.add(s.id)
    return raw


def read_legend(raw):
    """凡例: 端点の無い短い線と、同じ高さのテキスト（左: コネクタ、右: ケーブル）"""
    p = raw.page
    anchors = [it for it in p.items.values() if it.kind == 'text' and it.text in ('Connector', 'Cable')]
    for it in p.items.values():
        if it.kind == 'text' and re.search(r'VRRP|HSRP|GLBP', it.text) and it.owner is None:
            raw.legend_texts.append(it.text)
    if not anchors:
        return raw
    ax = min(a.rect[0] for a in anchors) - 200
    ay = min(a.rect[1] for a in anchors) - 50
    texts = [it for it in p.items.values() if it.kind in ('text', 'port') and it.owner is None and it.rect
             and it.rect[0] >= ax and it.rect[1] >= ay and it.text not in ('Connector', 'Cable')]
    for e in raw.edges['free']:
        it = e['item']
        sp, tp = p.edge_point(it, 'sourcePoint'), p.edge_point(it, 'targetPoint')
        if not sp or not tp:
            continue
        if sp[1] != tp[1] or sp[0] < ax:
            continue
        y = sp[1]
        x0, x1 = min(sp[0], tp[0]), max(sp[0], tp[0])
        row = [t for t in texts if abs((t.rect[1] + t.rect[3] / 2) - y) <= 12]
        left = [t for t in row if t.rect[0] + t.rect[2] <= x0 + 5]
        right = [t for t in row if t.rect[0] >= x1 - 5]
        if not left and not right:
            continue
        conn = max(left, key=lambda t: t.rect[0]).text if left else ''
        cable = min(right, key=lambda t: t.rect[0]).text if right else ''
        mark = endpoint_mark(e['start'])
        raw.legend[(width_class(e['width']), mark)] = dict(connector=conn, cable=cable, edge=it.id)
    return raw


def width_class(w):
    try:
        return 'thick' if float(w) >= 2.5 else 'thin'
    except ValueError:
        return 'thin'


def endpoint_mark(st):
    arrow, fill = st
    if arrow == 'oval':
        return 'black' if fill != '0' else 'white'
    return 'none'


def collect_notes(raw):
    p = raw.page
    for it in p.items.values():
        if it.kind in ('text', 'seglabel') and it.rect and len(it.text) >= 12 and re.search(r'[ぁ-んァ-ン一-龥]', it.text):
            raw.notes.append(it)
        if it.kind == 'text' and re.search(r'(Rack|ラック|フロア|Floor|階)', it.text) and len(it.text) < 30:
            raw.frames.append((it.text, it.rect, it.id))
    return raw


def split_port_name(text):
    """'Gi0/2 / PoE予備' → ('Gi0/2', 'PoE予備')"""
    t = text.replace(' / ', ' ').strip()
    m = PORTNAME_SPLIT.match(t)
    if m:
        return m.group(1).replace(' ', ''), m.group(2).strip()
    return t.split(' ')[0], ' '.join(t.split(' ')[1:])


def parse_seglabel(text):
    """'172.17.0.0/27EXT, VLAN2' → dict(name, vlan=(a,b)|None, cidr)"""
    cidr = CIDR_RE.search(text)
    vl = VLAN_RE.search(text)
    rest = text
    if cidr:
        rest = rest.replace(cidr.group(1), ' ')
    rest = ADDR_PLACEHOLDER_RE.sub(' ', rest)
    paren = re.search(r'[(（]([^)）]*)[)）]', rest)
    if vl:
        rest = rest[:vl.start()] + ' ' + rest[vl.end():] if vl.start() < len(rest) else rest
        rest = re.sub(r'VLAN\s*\d+(\s*-\s*\d+)?', ' ', rest, flags=re.I)
    rest = re.sub(r'[\s,/]+', ' ', rest).strip()
    name = rest.split(' ')[0] if rest else ''
    vlan = None
    if vl:
        v = vl.group(1).replace(' ', '')
        if '-' in v:
            a, b = v.split('-')
            vlan = (int(a), int(b))
        else:
            vlan = (int(v), int(v))
    note = paren.group(1).strip() if paren else ''
    if (name or note) and not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.\-]*$', name or ''):
        # 「VLAN90 (出向者向け/N社NW)」のように名前が英数字で書かれていない → VLAN 名は VLANnn、元の文字は説明に回す
        note = note or name
        name = ('VLAN%d' % vlan[0]) if vlan else ''
    return dict(name=name, vlan=vlan, cidr=cidr.group(1) if cidr else None, text=text, note=note)
