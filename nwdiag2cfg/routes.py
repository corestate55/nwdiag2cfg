"""静的経路（ナレッジ 5.5）。

経路は図にあるものだけ: 補助ページ（論理構成図）の点線矢印と、既定値ファイルの routes（優先）。
不足していそうな経路は足さず、L-05 で提案する（checks.py）。
"""
import fnmatch
import ipaddress
import re
from collections import defaultdict

from .model import Route


def build_routes(M):
    _site_names(M)
    proj = _project_routes(M)
    if M.aux is not None:
        for r in M.aux.routes:
            _aux_route(M, r, proj)
    _mgmt_routes(M)


def _site_names(M):
    """拠点名（東京など）→ 拠点。既定値ファイル > 拠点をまたぐ経路矢印からの推定"""
    if M.aux is None:
        return
    for r in M.aux.routes:
        m = re.match(r'^\s*(?:d\s+)?to\s*(\S+)', r['label'].replace('to ', 'to'))
        if not m:
            continue
        name = m.group(1)
        if name in M.site_names:
            continue
        src = {_dev_site(M, h) for h in r['src_hosts']} - {None}
        dst = {_dev_site(M, h) for h in r['dst_hosts']} - {None}
        if len(src) == 1 and len(dst) == 1 and src != dst:
            M.site_names[name] = dst.pop()
            M.guess('-', '拠点名「%s」' % name, M.site_names[name],
                    '論理構成図で別拠点の機器に向かう矢印のラベル（cell %s）' % r['id'])


def _dev_site(M, host):
    for d in M.devices:
        if d.cfgname == host or d.name == host:
            return d.site
    m = re.match(r'^([a-z0-9]+)-', host)
    return m.group(1) if m else None


def _find(M, host):
    for d in M.nw():
        if d.cfgname == host or (d.name == host and d.cfgname == d.name):
            return d
    return None


def _dest(M, label, dev):
    lab = label.replace(' ', '')
    lab = re.sub(r'^d(?=to|default)', '', lab)  # 「d」の付いたラベル（描画の残り）
    if 'default' in lab:
        return '0.0.0.0/0', 'default'
    m = re.search(r'to(.+)$', lab)
    if m:
        name = m.group(1)
        site = M.site_names.get(name)
        if site and site in M.site_block:
            blk, src = M.site_block[site]
            return str(blk), 'to%s（%s 拠点ブロック%s）' % (name, site, src)
        return '<TBD:%s_PREFIX>' % name, 'to%s（拠点ブロック不明）' % name
    return None, None


def _shared(M, dev, dsts):
    """dev と dsts が共有する L3 セグメントと next-hop"""
    from .build import seg_ident
    mine = {seg_ident(M, l3.segkey): l3 for l3 in dev.l3 if l3.segkey and l3.kind != 'mgmt' and l3.vrf is None}
    for d in dsts:
        for l3 in d.l3:
            if l3.segkey and seg_ident(M, l3.segkey) in mine and l3.kind != 'mgmt' and l3.vrf is None:
                sg = M.segments.get(l3.segkey)
                if len(dsts) > 1 and l3.vip is not None:
                    return l3.segkey, ip_of(M, sg, l3.vip), 'VIP .%d' % l3.vip, mine[seg_ident(M, l3.segkey)]
                return l3.segkey, ip_of(M, sg, l3.host, '%s_IP_%s' % (sg.name if sg else 'SEG', d.cfgname)), \
                    '%s の %s' % (d.cfgname, l3.badge_text or 'IP'), mine[seg_ident(M, l3.segkey)]
    return None, None, None, None


def ip_of(M, sg, host, tag=''):
    if sg is None or host is None or not sg.cidr or sg.cidr_tbd or sg.aggregate:
        tag = tag or (sg.name if sg else 'NEXTHOP')
        return '<TBD:%s>' % (tag if '_IP' in tag else tag + '_IP')
    n = ipaddress.ip_network(sg.cidr, strict=False)
    return str(n.network_address + host)


def _aux_route(M, r, proj):
    srcs = [d for d in (_find(M, h) for h in r['src_hosts']) if d is not None]
    dsts = [d for d in (_find(M, h) for h in r['dst_hosts']) if d is not None]
    for dev in srcs:
        dest, dtext = _dest(M, r['label'], dev)
        if dest is None:
            continue
        if (dev.cfgname, dest) in proj:
            continue
        cells = [r['id']]
        if dsts:
            key, nh, why, mine = _shared(M, dev, dsts)
            if key is None:
                M.F.add('L-04', 'ERROR', '%s → %s' % (dev.cfgname, r['dst_text']),
                        '経路「%s」の next-hop の機器と共通のセグメントが無い' % r['label'],
                        basis='論理構成図の矢印（cell %s）' % r['id'], recommend='矢印の先か、合成図の接続を確認する',
                        provisional='経路を設定しない', cells=cells)
                continue
            dev.routes.append(Route(dev, dest, nh, src='【論】', reason='論理構成図の矢印「%s」→ %s。next-hop は %s' % (
                r['label'], r['dst_text'].split(' / ')[-1], why), cells=cells, out_if=mine, label=dtext))
        else:
            ext = [l3 for l3 in dev.l3 if l3.kind == 'phys' and (M.segments.get(l3.segkey) and not M.segments[l3.segkey].vlan)]
            out = ext[0] if ext else None
            dev.routes.append(Route(dev, dest, '<TBD:%s_GW>' % (r['dst_text'] or 'NEXTHOP').replace(' ', '_'),
                                    src='【論】', reason='論理構成図の矢印「%s」→ %s。相手側の IP は図に無い' % (
                                        r['label'], r['dst_text']), cells=cells, out_if=out, label=dtext))


def _project_routes(M):
    done = set()
    for spec in M.project.routes:
        pat = spec.get('device', '')
        for dev in M.nw():
            if not fnmatch.fnmatch(dev.cfgname, pat):
                continue
            dest = spec.get('dest')
            nh = spec.get('next_hop')
            why = '既定値ファイルの routes'
            out = None
            if not nh and spec.get('next_hop_device'):
                dsts = [d for d in M.nw() if fnmatch.fnmatch(d.cfgname, spec['next_hop_device'])]
                key, nh, why2, out = _shared(M, dev, dsts)
                why += '（next-hop は %s）' % why2 if why2 else ''
            if not nh:
                nh = '<TBD:NEXTHOP>'
            dev.routes.append(Route(dev, dest, nh, vrf=spec.get('vrf'), src='【指定】', reason=why, out_if=out,
                                    label=dest))
            done.add((dev.cfgname, dest))
    return done


def _mgmt_routes(M):
    """管理 VRF のデフォルト経路（6.2: 管理セグメントの VIP または GW）、L2SW の default-gateway"""
    for dev in M.nw():
        mg = dev.mgmt
        if not mg:
            continue
        sg = M.segments.get(mg.get('segkey')) if mg.get('segkey') else None
        gw = None
        if sg is not None and sg.vip is not None:
            gw = ip_of(M, sg, sg.vip, 'MGMT_GW')
            why = '%s の VIP .%d' % (sg.name, sg.vip)
        else:
            gw = '<TBD:MGMT_GW_%s>' % dev.site.upper()
            why = '管理セグメントの GW が図に無い'
        if mg['kind'] in ('oob', 'r12'):
            if any(r.vrf == mg.get('vrf') for r in dev.routes):
                continue
            dev.routes.append(Route(dev, '0.0.0.0/0', gw, vrf=mg.get('vrf'), src='【推測】',
                                    reason='管理 VRF のデフォルト経路（6.2）。next-hop は %s' % why, label='mgmt default'))
        elif mg['kind'] == 'inband':
            mg['gateway'] = gw
            mg['gateway_why'] = why
