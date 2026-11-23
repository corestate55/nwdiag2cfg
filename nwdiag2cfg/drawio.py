"""drawio ファイルの読込と、ページ内の図形・線の基本情報（絶対座標・回転・テキスト）。

対応形式: .drawio / .xml（<mxfile>）、.drawio.svg（content 属性に mxfile を持つ SVG）。
ページが圧縮（Base64 + raw deflate + URL エンコード）されていても展開する。
"""
import base64
import hashlib
import html
import re
import urllib.parse
import zlib
import xml.etree.ElementTree as ET


class DrawioError(Exception):
    pass


def load_mxfile(path):
    try:
        raw = open(path, 'rb').read()
    except OSError as e:
        raise DrawioError('ファイルを読めません: %s (%s)' % (path, e))
    digest = hashlib.sha256(raw).hexdigest()
    src = raw.decode('utf-8', errors='replace')
    if src.lstrip().startswith('<mxfile'):
        return ET.fromstring(src), digest
    m = re.search(r'content="([^"]*)"', src)
    if not m:
        raise DrawioError('drawio データ（mxfile / content 属性）が見つかりません: %s' % path)
    return ET.fromstring(html.unescape(m.group(1))), digest


def page_names(mx):
    return [d.get('name') for d in mx.findall('diagram')]


def page_model(mx, name):
    for d in mx.findall('diagram'):
        if d.get('name') == name:
            m = d.find('mxGraphModel')
            if m is not None:
                return m
            data = (d.text or '').strip()
            try:
                raw = zlib.decompress(base64.b64decode(data), -15).decode('utf-8')
            except Exception as e:  # noqa
                raise DrawioError('ページ「%s」を展開できません: %s' % (name, e))
            return ET.fromstring(urllib.parse.unquote(raw))
    raise DrawioError('タブが見つかりません: %s（--list-tabs で一覧を確認してください）' % name)


def parse_style(s):
    d = {}
    for kv in (s or '').split(';'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            d[k] = v
        elif kv:
            d[kv] = ''
    return d


def clean_text(v):
    """HTML ラベルをプレーンテキストに。改行は ' / ' にする。"""
    v = re.sub(r'<br\s*/?>|</div>|</p>|<div[^>]*>', ' / ', v or '')
    v = re.sub(r'<[^>]+>', '', v)
    v = html.unescape(v).replace('\xa0', ' ')
    v = re.sub(r'\s+', ' ', v)
    v = re.sub(r'( / )+', ' / ', v)
    return v.strip(' /')


NEUTRAL = {'none', 'default', '#ffffff', '#000000', '#f5f5f5', 'light-dark(#ffffff,#121212)', 'inherit'}


class Item:
    def color(self):
        for k in ('fillColor', 'strokeColor'):
            v = self.style.get(k, '')
            if v and v.lower() not in NEUTRAL:
                return v.upper()
        return ''

    def stroke(self):
        v = self.style.get('strokeColor', '')
        return '' if not v or v.lower() in NEUTRAL else v.upper()

    def center(self):
        r = self.rect
        return (r[0] + r[2] / 2, r[1] + r[3] / 2)


class Page:
    def __init__(self, model, name):
        self.name = name
        self.items = {}
        self.order = []
        root = model.find('root')
        if root is None:
            raise DrawioError('ページ「%s」に root がありません' % name)
        for el in root:
            if el.tag == 'mxCell':
                c, label, props = el, el.get('value'), {}
            else:  # object / UserObject
                c = el.find('mxCell')
                if c is None:
                    continue
                label = el.get('label')
                props = {k: v for k, v in el.attrib.items() if k not in ('id', 'label', 'placeholders')}
            it = Item()
            it.id = el.get('id')
            it.raw = label or ''
            it.text = clean_text(label)
            it.style = parse_style(c.get('style'))
            it.props = props
            it.edge = c.get('edge') == '1'
            it.vertex = c.get('vertex') == '1'
            it.parent = c.get('parent')
            it.source = c.get('source')
            it.target = c.get('target')
            it.geo = c.find('mxGeometry')
            it.rect = None
            it.kind = None
            it.owner = None
            it.labels = []
            self.items[it.id] = it
            self.order.append(it.id)
        for it in self.items.values():
            if it.vertex:
                it.rect = self._rect(it)
        # 線のラベル（線を親に持つ子セル）
        for it in self.items.values():
            par = self.items.get(it.parent)
            if par is not None and par.edge and it.text:
                par.labels.append(it.text)
        for it in self.items.values():
            if it.edge and it.text:
                it.labels.insert(0, it.text)

    def _origin(self, it):
        x = y = 0.0
        seen = set()
        cur = it
        while cur is not None and cur.id not in seen:
            seen.add(cur.id)
            g = cur.geo
            if g is not None and g.get('relative') != '1' and not cur.edge:
                x += float(g.get('x', 0))
                y += float(g.get('y', 0))
            cur = self.items.get(cur.parent) if cur.parent else None
        return x, y

    def _rect(self, it):
        g = it.geo
        if g is None or g.get('relative') == '1':
            return None
        x, y = self._origin(it)
        w, h = float(g.get('width', 0)), float(g.get('height', 0))
        rot = it.style.get('rotation', '0') or '0'
        try:
            rot = float(rot) % 180
        except ValueError:
            rot = 0
        if abs(rot - 90) < 1:  # 90/270 度回転: 中心を保ったまま幅と高さを入れ替える
            cx, cy = x + w / 2, y + h / 2
            x, y, w, h = cx - h / 2, cy - w / 2, h, w
        return (x, y, w, h)

    def edge_point(self, it, which):
        """線の端点（sourcePoint/targetPoint）の絶対座標。無ければ None。"""
        if it.geo is None:
            return None
        for pt in it.geo.findall('mxPoint'):
            if pt.get('as') == which:
                par = self.items.get(it.parent)
                ox, oy = self._origin(par) if par is not None else (0, 0)
                return (ox + float(pt.get('x', 0) or 0), oy + float(pt.get('y', 0) or 0))
        return None

    def edge_points(self, it):
        """線の経路上の点（両端の位置が分かる場合は含める）。"""
        pts = []
        s = self.items.get(it.source)
        t = self.items.get(it.target)
        if s is not None and s.rect:
            pts.append(s.center())
        else:
            p = self.edge_point(it, 'sourcePoint')
            if p:
                pts.append(p)
        if it.geo is not None:
            arr = it.geo.find('Array')
            if arr is not None:
                par = self.items.get(it.parent)
                ox, oy = self._origin(par) if par is not None else (0, 0)
                for pt in arr.findall('mxPoint'):
                    pts.append((ox + float(pt.get('x', 0) or 0), oy + float(pt.get('y', 0) or 0)))
        if t is not None and t.rect:
            pts.append(t.center())
        else:
            p = self.edge_point(it, 'targetPoint')
            if p:
                pts.append(p)
        return pts


def rect_dist(r, pt):
    dx = max(r[0] - pt[0], 0, pt[0] - (r[0] + r[2]))
    dy = max(r[1] - pt[1], 0, pt[1] - (r[1] + r[3]))
    return (dx * dx + dy * dy) ** 0.5


def rect_gap(a, b):
    dx = max(b[0] - (a[0] + a[2]), 0, a[0] - (b[0] + b[2]))
    dy = max(b[1] - (a[1] + a[3]), 0, a[1] - (b[1] + b[3]))
    return (dx * dx + dy * dy) ** 0.5


def overlap(a, b, tol=0.0):
    return not (a[0] + a[2] + tol < b[0] or b[0] + b[2] + tol < a[0] or
                a[1] + a[3] + tol < b[1] or b[1] + b[3] + tol < a[1])


def center_in(r, b):
    cx, cy = r[0] + r[2] / 2, r[1] + r[3] / 2
    return b[0] <= cx <= b[0] + b[2] and b[1] <= cy <= b[1] + b[3]
