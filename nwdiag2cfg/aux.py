"""補助ページ（論理構成図・物理構成図）の読み取り。--aux-tab で指定したときだけ使う（D2）。

- セグメントのラベル（名前・VLAN・CIDR）: X-01、アドレス矛盾の解決（6.4）
- 注記（「〜ごとに1VLAN」）: 集約 VLAN の払い出し単位（5.4）
- 点線矢印の静的経路（default / to<拠点>）: 5.5
- ホスト名とテキストの一覧: N-03、X-03
"""
import re

from . import drawio as D
from . import extract as X

HOST_TOKEN = re.compile(r'\b([a-z][a-z0-9]*-[a-z]+[a-z0-9]*?)(\d+)((?:/\d+)*)\b', re.I)


def expand_hosts(text):
    out = []
    for m in HOST_TOKEN.finditer(text or ''):
        base, first, rest = m.group(1), m.group(2), m.group(3)
        out.append(base + first)
        for r in rest.split('/')[1:]:
            out.append(base + r.zfill(len(first)))
    return out


class AuxPage:
    def __init__(self, name, page, raw):
        self.name = name
        self.page = page
        self.raw = raw
        self.segments = []   # dict(name, vlan, cidr, text, id, rect)
        self.notes = []      # dict(text, id, rect, segment)
        self.routes = []     # dict(id, src_hosts, src_text, dst_hosts, dst_text, label, cells)
        self.hosts = set()
        self.texts = []


def load_aux(mx, name):
    page = D.Page(D.page_model(mx, name), name)
    raw = X.classify(page)
    X.classify_edges(raw)
    ap = AuxPage(name, page, raw)
    for it in page.items.values():
        if not it.vertex or not it.text or not it.rect:
            continue
        ap.texts.append(it.text)
        for h in expand_hosts(it.text):
            ap.hosts.add(h)
        if X.CIDR_RE.search(it.text) and X.VLAN_RE.search(it.text):
            pr = X.parse_seglabel(it.text)
            first = it.text.split(' / ')[0]
            pr['name'] = re.split(r'[,、]', first)[0].strip()
            pr.update(id=it.id, rect=it.rect)
            ap.segments.append(pr)
    for it in page.items.values():
        if it.vertex and it.rect and 'ごとに' in it.text:
            n = dict(text=it.text, id=it.id, rect=it.rect, segment=None)
            vl = X.VLAN_RE.search(it.text)
            best = None
            for s in ap.segments:
                if vl and s['vlan'] and vl.group(1).replace(' ', '') == ('%d-%d' % s['vlan'] if s['vlan'][0] != s['vlan'][1] else str(s['vlan'][0])):
                    best = (0, s)
                    break
                d = D.rect_gap(it.rect, s['rect'])
                if d <= 300 and (best is None or d < best[0]):
                    best = (d, s)
            if best:
                n['segment'] = best[1]
            ap.notes.append(n)
    _routes(ap)
    return ap


def _node_text(ap, item):
    """経路矢印の端の図形 → 近くのホスト名テキスト（または Internet など）"""
    if item is None or not item.rect:
        return None, []
    if item.text and (expand_hosts(item.text) or item.text):
        hs = expand_hosts(item.text)
        if hs:
            return item.text, hs
    best = None
    for it in ap.page.items.values():
        if it.vertex and it.rect and it.text and it is not item:
            d = D.rect_gap(it.rect, item.rect)
            if d <= 40:
                hs = expand_hosts(it.text)
                score = (0 if hs else 1, d)
                if best is None or score < best[0]:
                    best = (score, it.text, hs)
    if best:
        return best[1], best[2]
    return item.text or None, []


def _routes(ap):
    for e in ap.raw.edges.get('route', []):
        label = ' '.join(e['labels']).strip()
        if not label:
            continue
        st, sh = _node_text(ap, e['a'])
        tt, th = _node_text(ap, e['b'])
        ap.routes.append(dict(id=e['id'], src_text=st, src_hosts=sh, dst_text=tt, dst_hosts=th, label=label))


def merge_aux(aps):
    """--aux-tab を複数指定したときに1つにまとめる（ページ固有の判定は先頭のページで行う）"""
    if not aps:
        return None
    if len(aps) == 1:
        return aps[0]
    m = AuxPage('、'.join(a.name for a in aps), aps[0].page, aps[0].raw)
    for a in aps:
        m.segments += a.segments
        m.notes += a.notes
        m.routes += a.routes
        m.hosts |= a.hosts
        m.texts += a.texts
    return m
