"""合成テスト用の小さな物理・論理合成図（drawio）を作る。

    python3 tests/fixtures/make_fixtures.py   # tests/fixtures/*.drawio を作り直す

図の内容（lab 拠点）
- lab-core01 / lab-core02: L3SW の冗長ペア。GRT、DATA(VLAN10) と MGMT(VLAN9) の SVI、VRRP VIP
  （lab-core02 は 2.10 の省略で、横線・所属線を描かない）
- lab-acc01: L2SW。2台のコアに 1本ずつ
- lab-svr01: サーバー（DATA）
"""
import os
from xml.sax.saxutils import quoteattr

RED, PUR = '#CC0000', '#6600CC'


class D:
    def __init__(self):
        self.cells = []
        self.n = 1

    def v(self, text, x, y, w, h, style='rounded=0;whiteSpace=wrap;html=1;'):
        self.n += 1
        cid = 'c%d' % self.n
        self.cells.append('<mxCell id="%s" value=%s style=%s vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>'
                          % (cid, quoteattr(text), quoteattr(style), x, y, w, h))
        return cid

    def e(self, s, t, style='endArrow=none;html=1;'):
        self.n += 1
        cid = 'c%d' % self.n
        self.cells.append('<mxCell id="%s" style=%s edge="1" parent="1" source="%s" target="%s"><mxGeometry relative="1" as="geometry"/></mxCell>'
                          % (cid, quoteattr(style), s, t))
        return cid

    def seg(self, x, y, w, color):
        return self.v('', x, y, w, 8, 'rounded=0;html=1;fillColor=%s;strokeColor=none;' % color)

    def badge(self, text, x, y, color):
        return self.v(text, x, y, 30, 20, 'text;html=1;fontColor=%s;strokeColor=%s;' % (color, color))

    def port(self, name, x, y):
        return self.v(name, x, y, 60, 20)

    def box(self, x, y, w, h):
        return self.v('', x, y, w, h, 'rounded=0;whiteSpace=wrap;html=1;fillColor=none;')

    def xml(self, name):
        body = '<mxCell id="0"/><mxCell id="1" parent="0"/>' + ''.join(self.cells)
        return ('<mxfile><diagram id="p1" name=%s><mxGraphModel><root>%s</root></mxGraphModel></diagram></mxfile>\n'
                % (quoteattr(name), body))


def lab():
    d = D()
    logical = lambda c: 'endArrow=none;html=1;strokeColor=%s;' % c  # noqa: E731
    phys = 'endArrow=oval;startArrow=oval;html=1;strokeWidth=3;'
    # ---- lab-core01
    d.box(0, 0, 360, 240)
    d.v('lab-core01 / C社 L3switch 9000-24', 10, 5, 200, 30, 'text;html=1;')
    grt1 = d.v('GRT', 20, 40, 160, 30, 'rounded=1;html=1;strokeColor=#666666;')
    data1 = d.seg(20, 120, 300, RED)
    mgmt1 = d.seg(20, 150, 300, PUR)
    l_data = d.v('192.168.10.0/24 DATA, VLAN10', 230, 100, 120, 18, 'text;html=1;')
    l_mgmt = d.v('192.168.9.0/24 MGMT, VLAN9', 230, 160, 120, 18, 'text;html=1;')
    d.e(data1, l_data, 'endArrow=none;dashed=1;html=1;')
    d.e(mgmt1, l_mgmt, 'endArrow=none;dashed=1;html=1;')
    d.e(grt1, data1, logical(RED))
    d.e(grt1, mgmt1, logical(PUR))
    d.badge('.1', 60, 95, RED)
    d.badge('.1', 100, 125, PUR)
    p1 = d.port('Te0/1', 20, 220)
    p2 = d.port('Te0/2', 100, 220)
    p3 = d.port('Te0/24', 290, 100)
    d.e(p1, data1, logical(RED))
    d.e(p1, mgmt1, logical(PUR))
    d.e(p2, data1, logical(RED))
    d.e(p3, data1, logical(RED))
    d.e(p3, mgmt1, logical(PUR))
    # ---- lab-core02（省略形: 横線なし）
    d.box(500, 0, 360, 240)
    d.v('lab-core02 / C社 L3switch 9000-24', 510, 5, 200, 30, 'text;html=1;')
    grt2 = d.v('GRT', 520, 40, 160, 30, 'rounded=1;html=1;strokeColor=#666666;')
    d.e(grt1, grt2, 'endArrow=none;html=1;strokeColor=#808080;')
    d.v('vip .3', 400, 40, 50, 20, 'text;html=1;fontColor=#808080;strokeColor=#808080;')
    d.badge('.2', 560, 95, RED)
    q1 = d.port('Te0/1', 520, 220)
    q3 = d.port('Te0/24', 490, 100)
    d.e(p3, q3, phys)
    # ---- lab-acc01
    d.box(0, 400, 360, 200)
    d.v('lab-acc01 / C社 L2switch 1000-24', 10, 405, 200, 30, 'text;html=1;')
    a1 = d.port('Te0/1', 20, 400)
    a2 = d.port('Te0/2', 100, 400)
    a3 = d.port('Gi0/3', 20, 580)
    adata = d.seg(20, 500, 300, RED)
    d.v('DATA, VLAN10', 230, 480, 100, 18, 'text;html=1;')
    amgmt = d.seg(20, 530, 300, PUR)
    d.v('MGMT, VLAN9', 230, 540, 100, 18, 'text;html=1;')
    for a in (a1, a2, a3):
        d.e(a, adata, logical(RED))
    for a in (a1, a2):
        d.e(a, amgmt, logical(PUR))
    d.badge('.11', 200, 520, PUR)
    d.e(p1, a1, phys)
    d.e(q1, a2, phys)
    # ---- lab-svr01
    d.box(0, 700, 200, 100)
    d.v('lab-svr01 / Linux', 10, 705, 150, 30, 'text;html=1;')
    s0 = d.port('eth0', 20, 700)
    d.badge('.10', 80, 740, RED)
    d.e(a3, s0, phys.replace('strokeWidth=3', 'strokeWidth=1'))
    # ---- 凡例
    d.v('VRRP VIP', 1000, 0, 60, 20, 'text;html=1;')
    return d.xml('物理・論理')


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, 'lab.drawio'), 'w', encoding='utf-8') as f:
        f.write(lab())


if __name__ == '__main__':
    main()
