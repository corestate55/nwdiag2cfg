"""中間表現（ナレッジ 3.3 の台帳4表のもとになるデータ）"""


class Device:
    def __init__(self, uid, name, cfgname, model, label_id, box, box_id):
        self.uid = uid
        self.name = name            # 図のホスト名
        self.cfgname = cfgname      # 出力に使う名前（重複は -dupN）
        self.model = model
        self.label_id = label_id
        self.box = box
        self.box_id = box_id
        self.role = 'other'         # fw / router / l3sw / l2sw / ap / server / other
        self.cls = 'other'          # nw / ap / server / other
        self.site = ''
        self.os = None              # iosxe / isr / asa
        self.platform = None        # 機種判定の記録
        self.ports = {}             # name -> Port
        self.routings = []          # routing items（GRT / vrf）
        self.badges = []            # (item, color, host, text)
        self.seg_items = []         # 箱の中の横線 item
        self.pair = None            # 相手の Device
        self.primary = True
        self.l3 = []                # L3If
        self.mgmt = None            # dict(kind=oob|inband|r12, ...)
        self.routes = []            # Route
        self.vips = []

    def __repr__(self):
        return '<Device %s>' % self.cfgname

    @property
    def is_nw(self):
        return self.cls == 'nw'


class Port:
    def __init__(self, dev, name, note, item, kind='port'):
        self.dev = dev
        self.name = name            # 図の名前（Te0/1）
        self.note = note            # 「PoE予備」など
        self.item = item
        self.cell = item.id if item is not None else None
        self.kind = kind            # port / po / virtual
        self.members = []           # Po のメンバー Port
        self.po = None              # メンバーなら所属 Po
        self.links = []             # Link
        self.memb = {}              # segkey -> Membership（L2 所属）
        self.l3 = None              # L3 ポートなら L3If
        self.shutdown_reason = None

    def __repr__(self):
        return '<Port %s %s>' % (self.dev.cfgname, self.name)

    @property
    def is_range(self):
        return '-' in self.name.split('/')[-1]

    def eff_memb(self):
        """Po メンバーは Po の所属を使う"""
        if self.po is not None and self.po.memb:
            return self.po.memb
        return self.memb


class Membership:
    def __init__(self, segkey, how, cells=(), color_ok=True, note=''):
        self.segkey = segkey
        self.how = how              # edge / label / dangling / symmetry / server / override
        self.cells = [c for c in cells if c]
        self.color_ok = color_ok
        self.note = note


class Segment:
    def __init__(self, key):
        self.key = key              # (site, color)
        self.site, self.color = key
        self.name = ''
        self.vlan = None            # (a, b)
        self.cidr = None
        self.cidr_src = '【図】'
        self.cidr_tbd = False
        self.labels = []            # (parsed, item id, how)
        self.items = []             # segment item ids
        self.unit = None            # 払い出し単位（集約のとき）dict(text, source, cell)
        self.vip = None
        self.vip_cell = None

    @property
    def aggregate(self):
        return self.vlan is not None and self.vlan[0] != self.vlan[1]

    @property
    def vid(self):
        return self.vlan[0] if self.vlan and not self.aggregate else None

    def vlan_text(self):
        if not self.vlan:
            return ''
        return str(self.vlan[0]) if self.vlan[0] == self.vlan[1] else '%d-%d' % self.vlan

    def tag(self):
        return '%s_%s' % (self.name or 'SEG', self.site.upper())

    def __repr__(self):
        return '<Seg %s %s VLAN%s %s>' % (self.site, self.name, self.vlan_text(), self.cidr)


class Link:
    def __init__(self, a, b, edge, width, mark_a, mark_b, color, inferred=False, ext_name=''):
        self.a = a                  # Port
        self.b = b                  # Port or None（外部の図形）
        self.edge = edge
        self.width = width
        self.mark = {id(a): mark_a}
        if b is not None:
            self.mark[id(b)] = mark_b
        self.mark_ext = mark_b
        self.color = color
        self.inferred = inferred
        self.ext_name = ext_name

    def other(self, p):
        return self.b if p is self.a else self.a

    def mark_of(self, p):
        return self.mark.get(id(p), 'none')


class L3If:
    def __init__(self, dev, segkey, vrf, how, cells=()):
        self.dev = dev
        self.segkey = segkey
        self.vrf = vrf              # None=GRT
        self.how = how
        self.cells = [c for c in cells if c]
        self.host = None            # int / None(TBD)
        self.badge_text = None
        self.badge_cell = None
        self.port = None            # L3 物理ポート / Tunnel なら Port
        self.kind = 'svi'           # svi / phys / bvi / mgmt
        self.vip = None
        self.fhrp_group = None
        self.members = []           # BVI / スイッチポートのメンバー


class Route:
    def __init__(self, dev, dest, nh, vrf=None, src='', reason='', cells=(), out_if=None, label=''):
        self.dev = dev
        self.dest = dest            # '0.0.0.0/0' or CIDR or '<TBD:...>'
        self.nh = nh                # IP or '<TBD:...>'
        self.vrf = vrf
        self.src = src              # 根拠ラベル
        self.reason = reason
        self.cells = [c for c in cells if c]
        self.out_if = out_if
        self.label = label
