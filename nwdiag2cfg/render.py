"""コンフィグの描画（Cisco フォールバックの3記法: IOS-XE スイッチ、ISR ルーター、ASA）。

出力の約束（ナレッジ 8.1 TBD の出力規則）
- <TBD:...> は有効な設定行のまま置く（コメントアウトしない）
- 図で使用中のポート・SVI・経路は shutdown しない。shutdown は「予備」明示と接続先不明の未接続線だけ
- 懸念のある行には ! WARN {{F:key}} を付ける（指摘IDは最後に置き換える）
"""
import ipaddress
import re

from . import extract as X
from .build import seg_ident, _port_sort, unit_token
from .routes import ip_of

LONG = [('TwentyFiveGigE', 'Tw'), ('TenGigabitEthernet', 'Te'), ('FortyGigabitEthernet', 'Fo'),
        ('HundredGigE', 'Hu'), ('GigabitEthernet', 'Gi'), ('FastEthernet', 'Fa'), ('Port-channel', 'Po'),
        ('Tunnel', 'Tun'), ('Tunnel', 'Tu'), ('Loopback', 'Lo'), ('Vlan', 'Vl'), ('Ethernet', 'Eth')]


def long_name(name, os_='iosxe'):
    if re.match(r'^mgmt\d*$', name, re.I):
        return 'Management0/0' if os_ == 'asa' else 'GigabitEthernet0/0'
    for full, short in LONG:
        if name.startswith(short) and not name.startswith(full):
            rest = name[len(short):]
            if re.match(r'^[\d/]', rest):
                return full + rest
    return name


def range_name(name, os_):
    """Gi0/3-20 → GigabitEthernet0/3 - 20"""
    m = re.match(r'^(.*?)(\d+)-(\d+)$', name)
    if not m:
        return long_name(name, os_)
    return '%s%s - %s' % (long_name(m.group(1) + m.group(2), os_), '', m.group(3))


def mask(cidr):
    return str(ipaddress.ip_network(cidr, strict=False).netmask)


def vlan_list(items):
    """[int | (a,b) | '<TBD:..>'] → '2,9-11,300-399,<TBD:..>'"""
    nums = set()
    toks = []
    for x in items:
        if isinstance(x, tuple):
            nums.update(range(x[0], x[1] + 1))
        elif isinstance(x, int):
            nums.add(x)
        elif x not in toks:
            toks.append(x)
    out = []
    s = sorted(nums)
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[j] + 1:
            j += 1
        out.append(str(s[i]) if i == j else '%d-%d' % (s[i], s[j]))
        i = j + 1
    return ','.join(out + toks)


class Cfg:
    def __init__(self, dev):
        self.dev = dev
        self.lines = []
        self.blocks = []      # (タイトル, 行の範囲) 根拠表用
        self.port_vlans = {}  # 期待値: interface 名 -> ('access'|'trunk', set(token))
        self.svis = []        # (interface 名, vlan token)
        self.ifmap = {}       # interface 名 -> Port

    def add(self, *ls):
        self.lines.extend(ls)

    def text(self):
        return '\n'.join(self.lines) + '\n'


def _warn(M, dev, port=None):
    out = []
    for f in M.F.items:
        if (dev.cfgname, port) in f.refs:
            out.append('{{F:%s}}' % f.key)
    return out


def _warn_comment(M, dev, port=None):
    ids = _warn(M, dev, port)
    return (' ! WARN %s' % ' '.join(ids)) if ids else ''


# ---------------------------------------------------------------- ポートの VLAN
def port_vlan_items(M, pt):
    """(mode, items, notes)。items は vlan_list に渡す形。所属が無ければ (None, [], [])"""
    memb = pt.eff_memb()
    if not memb:
        return None, [], []
    peer_devs = set()
    for x in ([pt] + (pt.members if pt.kind == 'po' else [])):
        for lk in x.links:
            o = lk.other(x)
            if o is not None:
                peer_devs.add(o.dev)
    items, notes = [], []
    keys = sorted(memb, key=lambda k: (M.segments[k].vlan or (99999, 0)) if k in M.segments else (99999, 0))
    access = len(keys) == 1
    for k in keys:
        sg = M.segments.get(k)
        if sg is None or not sg.vlan:
            continue
        if sg.aggregate:
            tok = None
            if sg.unit and sg.unit.get('group'):
                tok = unit_token(M, sg, pt.dev)
                if tok is None:
                    for pd in peer_devs:
                        tok = unit_token(M, sg, pd)
                        if tok:
                            break
            if tok:
                items.append(tok)
                notes.append('%s は払い出し単位（%s）の機器向けなので <TBD>（5.4）' % (sg.name, sg.unit['text']))
            elif access:
                items.append('<TBD:%s_VLAN>' % sg.name)
                notes.append('%s は VLAN 範囲なので access の VLAN は <TBD>' % sg.name)
            else:
                items.append(sg.vlan)
        else:
            items.append(sg.vlan[0])
    if not items:
        return None, [], []
    mode = 'access' if access else 'trunk'
    return mode, items, notes


def _desc(M, pt):
    peers = []
    tgts = pt.members if pt.kind == 'po' and pt.members else [pt]
    for x in tgts:
        for lk in x.links:
            o = lk.other(x)
            if o is not None:
                peers.append((o.dev.cfgname, o.po.name if (pt.kind == 'po' and o.po is not None) else o.name, lk, x))
            else:
                peers.append((lk.ext_name or '外部', '', lk, x))
    if not peers:
        if pt.shutdown_reason:
            return pt.shutdown_reason
        return pt.note or ('（図に物理リンクの線なし）' if pt.memb and pt.kind == 'port' else '')
    seen = []
    for p in peers:
        if (p[0], p[1]) not in [(s[0], s[1]) for s in seen]:
            seen.append(p)
    d, n, lk, x = seen[0]
    cable = ''
    if pt.kind != 'po':
        leg = M.cable_legend.get((X.width_class(lk.width), lk.mark_of(x)))
        if leg:
            cable = ' [%s %s]' % (leg['connector'], leg['cable']) if leg['connector'] else ' [%s]' % leg['cable']
    inf = ' (推定接続)' if lk.inferred else ''
    more = ' ほか' if len(seen) > 1 else ''
    return ('to %s %s%s%s%s' % (d, n, more, cable, inf)).replace('  ', ' ').strip()


# ---------------------------------------------------------------- 共通
def header(M, dev, meta):
    return ['! ==== %s ====' % dev.cfgname,
            '! 生成: nwdiag2cfg %s / 入力: %s / タブ: %s' % (meta['version'], meta['file'], meta['tab']),
            '! 記法: %s（%s）' % ({'iosxe': 'Cisco IOS-XE', 'isr': 'Cisco IOS-XE (ISR)', 'asa': 'Cisco ASA'}[dev.os],
                                 dev.platform['judge'] if dev.platform else ''),
            '! <TBD:...> は投入前に置換が必要（configs.md の TBD 一覧）',
            '!']


def render_all(M, meta):
    out = {}
    for dev in sorted(M.nw(), key=lambda d: d.cfgname):
        if dev.os == 'asa':
            c = render_asa(M, dev, meta)
        elif dev.os == 'isr':
            c = render_ios(M, dev, meta, router=True)
        else:
            c = render_ios(M, dev, meta)
        out[dev.cfgname] = c
    return out


def _ip_line(M, l3, dev, tag=None):
    sg = M.segments.get(l3.segkey) if l3.segkey else None
    if sg is None or not sg.cidr or sg.cidr_tbd:
        name = sg.name if sg else (l3.port.name.replace('/', '-') if l3.port is not None else 'SEG')
        return 'ip address <TBD:%s_IP_%s> <TBD:%s_MASK>' % (name, dev.cfgname, name)
    if sg.aggregate:
        return 'ip address <TBD:%s_IP_%s> <TBD:%s_MASK>' % (sg.name, dev.cfgname, sg.name)
    if l3.host is None:
        ip = M.project.ipam_for(dev.cfgname, sg.name)
        if ip:
            return 'ip address %s %s' % (ip, mask(sg.cidr))
        return 'ip address <TBD:%s_IP_%s> %s' % (sg.name, dev.cfgname, mask(sg.cidr))
    n = ipaddress.ip_network(sg.cidr, strict=False)
    return 'ip address %s %s' % (n.network_address + l3.host, mask(sg.cidr))


def _fhrp_lines(M, dev, l3, sg):
    if l3.vip is None or sg is None:
        return []
    proto = M.project.get('fhrp_protocol')
    if proto == 'legend':
        leg = ' '.join(M.raw.legend_texts)
        proto = 'hsrp' if 'HSRP' in leg else 'vrrp'
        M.project.note_default('fhrp_protocol', [dev.cfgname])
    fmt = M.project.get('fhrp_format')
    M.project.note_default('fhrp_format', [dev.cfgname])
    M.project.note_default('fhrp_group', [dev.cfgname])
    M.project.note_default('fhrp_priority_primary', [dev.cfgname])
    M.project.note_default('fhrp_preempt', [dev.cfgname])
    grp = sg.vlan[0] if sg.vlan and not sg.aggregate and sg.vlan[0] <= 255 else None
    g = str(grp) if grp else '<TBD:%s_VRRP_GROUP>' % sg.name
    if sg.aggregate or not sg.cidr or sg.cidr_tbd:
        vip = '<TBD:%s_VIP>' % sg.name
    else:
        vip = ip_of(M, sg, l3.vip)
    pri = M.project.get('fhrp_priority_primary') if dev.primary else None
    pre = M.project.get('fhrp_preempt')
    out = []
    if proto == 'hsrp':
        out.append(' standby %s ip %s' % (g, vip))
        if pri:
            out.append(' standby %s priority %s' % (g, pri))
        if pre:
            out.append(' standby %s preempt' % g)
    elif fmt == 'legacy':
        out.append(' vrrp %s ip %s' % (g, vip))
        if pri:
            out.append(' vrrp %s priority %s' % (g, pri))
        if not pre:
            out.append(' no vrrp %s preempt' % g)
    else:
        out.append(' vrrp %s address-family ipv4' % g)
        out.append('  address %s primary' % vip)
        if pri:
            out.append('  priority %s' % pri)
        if pre:
            out.append('  preempt')
        out.append(' exit-vrrp')
    return out


def _uses_vrrpv3(M, dev):
    return any(l3.vip is not None for l3 in dev.l3) and M.project.get('fhrp_format') == 'vrrpv3' and \
        (M.project.get('fhrp_protocol') in ('legend', 'vrrp')) and 'HSRP' not in ' '.join(M.raw.legend_texts)


def _vrfs(dev):
    v = []
    for l3 in dev.l3 + ([dev.mgmt['l3']] if dev.mgmt and dev.mgmt.get('l3') else []):
        if l3.vrf and l3.vrf not in v:
            v.append(l3.vrf)
    return v


def _route_line(M, dev, r, asa=False):
    if r.dest.startswith('<'):
        dst = '%s <TBD:MASK>' % r.dest
    else:
        n = ipaddress.ip_network(r.dest, strict=False)
        dst = '%s %s' % (n.network_address, n.netmask)
    cm = ' ! %s %s' % (r.src, r.label) if r.label else ' ! %s' % r.src
    if asa:
        ifn = _asa_nameif(M, dev, r.out_if) if r.out_if is not None else '<TBD:NAMEIF>'
        return 'route %s %s %s%s' % (ifn, dst, r.nh, cm)
    if r.vrf:
        return 'ip route vrf %s %s %s%s' % (r.vrf, dst, r.nh, cm)
    return 'ip route %s %s%s' % (dst, r.nh, cm)


def _services(M, dev, asa=False):
    s = M.project.services
    out = ['!']
    ntp = s.get('ntp') or ['<TBD:NTP_SERVER>']
    for x in ntp:
        out.append('ntp server %s' % x)
    if not asa:
        for x in s.get('syslog') or ['<TBD:SYSLOG_SERVER>']:
            out.append('logging host %s' % x)
    return out


# ---------------------------------------------------------------- IOS-XE（スイッチ・ルーター）
def render_ios(M, dev, meta, router=False):
    c = Cfg(dev)
    c.add(*header(M, dev, meta))
    c.add('hostname %s%s' % (dev.cfgname, _warn_comment(M, dev, None) if dev.cfgname != dev.name else ''))
    c.add('!')
    if dev.role == 'l3sw':
        c.add('ip routing', '!')
    for v in _vrfs(dev):
        c.add('vrf definition %s' % v, ' address-family ipv4', ' exit-address-family', '!')
    if _uses_vrrpv3(M, dev):
        c.add('fhrp version vrrp v3', '!')
    # STP
    loops = [k for k, nodes in getattr(M, 'loops', {}).items() if dev.uid in nodes]
    if loops and dev.role in ('l3sw', 'l2sw', 'router'):
        M.project.note_default('stp_mode', [dev.cfgname])
        c.add('spanning-tree mode %s ! 【一般】L2 ループがあるため（V-06）' % M.project.get('stp_mode'))
        if dev.pair is not None and dev.role == 'l3sw' and any(l3.vip is not None for l3 in dev.l3):
            vl = []
            for k in loops:
                sg = M.segments.get(k)
                if sg and sg.vlan:
                    vl.append(sg.vlan)
            if vl:
                c.add('spanning-tree vlan %s root %s ! 【推測】冗長ペアの%s' % (
                    vlan_list(vl), 'primary' if dev.primary else 'secondary', '01号機をルート' if dev.primary else '02号機をセカンダリ'))
        c.add('!')
    # VLAN 定義
    keys = set()
    for pt in dev.ports.values():
        keys.update(pt.eff_memb())
    for l3 in dev.l3:
        if l3.kind == 'svi' and l3.segkey:
            keys.add(l3.segkey)
    segs = sorted([M.segments[k] for k in keys if k in M.segments and M.segments[k].vlan], key=lambda s: s.vlan)
    for sg in segs:
        if sg.aggregate:
            c.add('vlan %s ! %s（集約表現: 個々の VLAN 名は <TBD>）' % (sg.vlan_text(), sg.name))
        else:
            c.add('vlan %s' % sg.vlan_text(), ' name %s' % sg.name)
    if segs:
        c.add('!')
    # SVI
    for l3 in sorted([x for x in dev.l3 if x.kind == 'svi'], key=lambda x: (M.segments[x.segkey].vlan or (0, 0)) if x.segkey in M.segments else (0, 0)):
        sg = M.segments.get(l3.segkey)
        if sg is None or not sg.vlan:
            continue
        if sg.aggregate:
            vid = '<TBD:%s_VLAN_ID>' % sg.name
            c.add('! --- %s: VLAN%s の各 VLAN に同じ形の SVI を作る（テンプレート、5.4） ---' % (sg.name, sg.vlan_text()))
        else:
            vid = str(sg.vlan[0])
        c.svis.append(('Vlan' + vid, vid))
        c.add('interface Vlan%s' % vid)
        c.add(' description %s %s' % (sg.name, sg.cidr if sg.cidr and not sg.cidr_tbd else '<TBD:%s_CIDR>' % sg.name))
        if l3.vrf:
            c.add(' vrf forwarding %s' % l3.vrf)
        note = ''
        if sg.cidr_src == '【論】':
            note = ' ! 【論】合成図のラベルと違うため論理構成図の値'
        c.add(' ' + _ip_line(M, l3, dev) + note)
        c.add(*_fhrp_lines(M, dev, l3, sg))
        if dev.mgmt and dev.mgmt.get('l3') is l3:
            pass
        c.add('!')
    # ポート
    pos = sorted([p for p in dev.ports.values() if p.kind == 'po'], key=lambda p: _port_sort(p.name))
    phys = sorted([p for p in dev.ports.values() if p.kind in ('port', 'virtual')], key=lambda p: _port_sort(p.name))
    for pt in pos + phys:
        _ios_port(M, c, dev, pt, router)
    # 管理
    if dev.mgmt and dev.mgmt['kind'] == 'inband' and dev.role == 'l2sw':
        gw = dev.mgmt.get('gateway')
        if gw:
            c.add('ip default-gateway %s ! 【推測】%s' % (gw, dev.mgmt.get('gateway_why', '')), '!')
    # 経路
    rs = sorted(dev.routes, key=lambda r: (r.vrf or '', r.dest != '0.0.0.0/0', r.dest))
    for r in rs:
        c.add(_route_line(M, dev, r))
    if rs:
        c.add('!')
    c.add(*_services(M, dev))
    c.add('!', 'end')
    return c


def _ios_port(M, c, dev, pt, router):
    if pt.l3 is not None:
        _ios_l3_port(M, c, dev, pt)
        return
    if pt.kind == 'port' and not pt.links and not pt.memb and not pt.shutdown_reason and '予備' not in pt.note and \
            '未使用' not in pt.note:
        if M.project.get('unused_ports') == 'shutdown':
            c.add('interface %s' % long_name(pt.name), ' shutdown ! 未使用（既定値ファイル）', '!')
        return
    is_range = pt.is_range
    ifname = range_name(pt.name, dev.os) if is_range else long_name(pt.name, dev.os)
    c.add(('interface range %s' if is_range else 'interface %s') % ifname + ('' if long_name(pt.name) == pt.name or is_range else ''))
    c.ifmap[ifname] = pt
    desc = _desc(M, pt)
    if desc:
        c.add(' description %s' % desc)
    nw = getattr(pt, 'name_warn', None)
    if pt.shutdown_reason or '予備' in pt.note or '未使用' in pt.note:
        c.add(' shutdown ! %s' % (pt.shutdown_reason or '図に「%s」と明示（R14）' % pt.note) + _warn_comment(M, dev, pt.name))
        c.add('!')
        return
    mode, items, notes = port_vlan_items(M, pt)
    w = _warn_comment(M, dev, pt.name)
    if mode == 'access':
        c.add(' switchport mode access', ' switchport access vlan %s%s' % (vlan_list(items), w))
        c.port_vlans[ifname] = ('access', items)
    elif mode == 'trunk':
        M.project.note_default('trunk_extra', [dev.cfgname])
        for x in M.project.get('trunk_extra'):
            if 'encapsulation' in x:
                c.add(' ' + x)
        c.add(' switchport mode trunk', ' switchport trunk allowed vlan %s%s' % (vlan_list(items), w))
        for x in M.project.get('trunk_extra'):
            if 'encapsulation' not in x:
                c.add(' ' + x)
        c.port_vlans[ifname] = ('trunk', items)
    else:
        c.add(' ! 所属する VLAN が図に無い%s' % w)
    for n in notes:
        c.add(' ! %s' % n)
    if nw:
        c.add(' ! 図のポート名のまま（冗長ペアの対称位置は %s。誤記の可能性）' % nw)
    if pt.po is not None:
        M.project.note_default('lag_mode', [dev.cfgname])
        c.add(' channel-group %s mode %s' % (re.sub(r'\D', '', pt.po.name) or '1', M.project.get('lag_mode')))
    # 端末・サーバー・AP 向け
    peers = [lk.other(pt) for lk in pt.links]
    ext = [o for o in peers if o is None or not o.dev.is_nw]
    if ext and pt.kind == 'port' and mode:
        c.add(' spanning-tree portfast%s' % (' trunk' if mode == 'trunk' else ''))
    if any(o is not None and o.dev.cls == 'ap' for o in peers) or 'PoE' in pt.note:
        c.add(' power inline auto ! 【図】PoE（AP 接続）')
    c.add('!')


def _ios_l3_port(M, c, dev, pt):
    l3 = pt.l3
    ifname = long_name(pt.name, dev.os)
    c.add('interface %s%s' % (ifname, ' ! 図の「%s」' % pt.name if ifname != long_name(pt.name) or pt.name.lower().startswith('mgmt') else ''))
    desc = _desc(M, pt)
    if desc:
        c.add(' description %s' % desc)
    if l3.vrf:
        c.add(' vrf forwarding %s' % l3.vrf)
    if not dev.role == 'l3sw' and dev.os == 'iosxe' or dev.role == 'l3sw':
        if l3.kind != 'mgmt' and dev.role in ('l3sw', 'l2sw'):
            c.add(' no switchport')
    tag = ' ! 【推測】R12' if (dev.mgmt and dev.mgmt.get('l3') is l3 and dev.mgmt['kind'] == 'r12') else ''
    c.add(' ' + _ip_line(M, l3, dev) + tag)
    if pt.kind == 'virtual' and pt.name.lower().startswith('tu'):
        c.add(' tunnel source <TBD:TUNNEL_SOURCE>', ' tunnel destination <TBD:TUNNEL_DESTINATION>')
    c.add('!')


# ---------------------------------------------------------------- ASA
def _asa_nameif(M, dev, l3):
    if l3 is None:
        return '<TBD:NAMEIF>'
    sg = M.segments.get(l3.segkey) if l3.segkey else None
    if l3.kind == 'bvi':
        return _asa_member_nameif(l3.members[0]) if l3.members else 'inside'
    if sg is not None and not sg.vlan and 'INET' in (sg.name or '').upper():
        return 'outside'
    if l3.port is not None and l3.port.kind == 'virtual':
        return (sg.name if sg else 'tunnel').lower()
    if sg is not None:
        return re.sub(r'[^a-z0-9_-]', '', sg.name.lower()) or 'inside'
    return 'inside'


def _asa_member_nameif(pt):
    peer = None
    for lk in pt.links:
        o = lk.other(pt)
        if o is not None:
            peer = o.dev.cfgname
    return ('to-%s' % peer) if peer else pt.name.replace('/', '_').lower()


def render_asa(M, dev, meta):
    c = Cfg(dev)
    c.add(*header(M, dev, meta))
    c.add('hostname %s' % dev.cfgname, '!')
    outside = None
    for l3 in dev.l3:
        if _asa_nameif(M, dev, l3) == 'outside':
            outside = l3
    bvis = [l3 for l3 in dev.l3 if l3.kind == 'bvi']
    for pt in sorted(dev.ports.values(), key=lambda p: _port_sort(p.name)):
        l3 = pt.l3
        bv = next((b for b in bvis if pt in b.members), None)
        if l3 is None and bv is None and not pt.links:
            continue
        ifname = 'Tunnel%s' % re.sub(r'\D', '', pt.name) if pt.kind == 'virtual' and pt.name.lower().startswith('tu') else long_name(pt.name, 'asa')
        c.add('interface %s' % ifname)
        c.ifmap[ifname] = pt
        d = _desc(M, pt)
        if d:
            c.add(' description %s' % d)
        if pt.shutdown_reason:
            c.add(' shutdown ! %s' % pt.shutdown_reason, '!')
            continue
        if bv is not None:
            sg = M.segments.get(bv.segkey)
            c.add(' bridge-group %s' % (sg.vlan[0] if sg and sg.vlan else 1), ' nameif %s' % _asa_member_nameif(pt),
                  ' security-level 100' + _warn_comment(M, dev, pt.name))
            c.port_vlans[ifname] = ('access', [sg.vlan[0]] if sg and sg.vlan else [])
        elif l3 is not None:
            nif = _asa_nameif(M, dev, l3)
            c.add(' nameif %s' % nif, ' security-level %d' % (0 if nif == 'outside' else 100))
            c.add(' ' + _ip_line(M, l3, dev))
            if ifname.startswith('Tunnel'):
                c.add(' tunnel source interface %s' % (_asa_nameif(M, dev, outside) if outside else '<TBD:NAMEIF>'),
                      ' tunnel destination <TBD:TUNNEL_PEER>', ' tunnel mode ipsec ipv4',
                      ' tunnel protection ipsec profile <TBD:IPSEC_PROFILE>')
        else:
            c.add(' ! 所属する L3 が図に無い' + _warn_comment(M, dev, pt.name))
        c.add('!')
    for bv in bvis:
        sg = M.segments.get(bv.segkey)
        n = sg.vlan[0] if sg and sg.vlan else 1
        c.add('interface BVI%s' % n, ' description %s（%s）' % (sg.name if sg else '', '+'.join(m.name for m in bv.members)),
              ' ' + _ip_line(M, bv, dev) + ' ! 【推測】同一セグメントの2ポートを BVI で表現（R10）', '!')
        c.svis.append(('BVI%s' % n, str(n)))
    if bvis:
        c.add('same-security-traffic permit inter-interface', '!')
    for r in sorted(dev.routes, key=lambda r: (r.dest != '0.0.0.0/0', r.dest)):
        c.add(_route_line(M, dev, r, asa=True))
    if dev.routes:
        c.add('!')
    if outside is not None:
        blk = M.site_block.get(dev.site)
        c.add('! --- NAT・ポリシーの雛形（【一般】6.2） ---')
        c.add('object network OBJ-%s-INTERNAL' % dev.site.upper(),
              ' subnet %s %s' % ((blk[0].network_address, blk[0].netmask) if blk else ('<TBD:INTERNAL_NET>', '<TBD:MASK>')),
              ' nat (any,outside) dynamic interface')
        c.add('access-list OUTSIDE-IN extended <TBD:FW_POLICY>', 'access-group OUTSIDE-IN in interface outside', '!')
    c.add(*_services(M, dev, asa=True))
    c.add('!', 'end')
    return c
