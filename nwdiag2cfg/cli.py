"""コマンドライン（設計計画 2章）。

    nwdiag2cfg -f <drawio> -t <物理・論理合成図タブ> [-o DIR] [--aux-tab TAB ...] [-p project.toml]
               [--force] [--debug] [--prev-review review.csv] [--fail-on error|warn|never] [--list-tabs]

終了コード: 0 生成できた（指摘があっても 0。--fail-on で変更） / 1 --fail-on の条件に当たった / 2 入力エラー
"""
import argparse
import datetime
import json
import os
import re
import shutil
import sys

from . import __version__
from . import aux as A
from . import build as B
from . import checks as C
from . import drawio as D
from . import extract as X
from . import report as R
from . import routes as RT
from .findings import Findings
from .project import load_project, ProjectError
from .render import render_all
from .selfcheck import run_selfcheck


def parse_args(argv):
    p = argparse.ArgumentParser(prog='nwdiag2cfg', description='物理・論理合成図（drawio）から NW 機器コンフィグとレビューを生成する')
    p.add_argument('-f', '--file', required=True, help='入力の drawio ファイル（.drawio / .drawio.svg / .xml）')
    p.add_argument('-t', '--tab', help='物理・論理合成図のタブ名')
    p.add_argument('-o', '--output', help='出力先ディレクトリ（既定: ./<入力ファイル名の語幹>）')
    p.add_argument('--aux-tab', action='append', default=[], metavar='TAB',
                   help='補助ページ（論理構成図など）のタブ名。経路・アドレス・X-01〜03 に使う。複数指定可')
    p.add_argument('-p', '--project', help='既定値ファイル（TOML）')
    p.add_argument('--force', action='store_true', help='出力先が既にあれば消して作り直す')
    p.add_argument('--debug', action='store_true', help='debug/model.json と debug/extract.md も出力する')
    p.add_argument('--prev-review', metavar='CSV', help='前回の review.csv。状態・確認者・メモを同じ指摘に引き継ぐ')
    p.add_argument('--fail-on', choices=['error', 'warn', 'never'], default='never',
                   help='指摘がこの重要度以上なら終了コード 1（既定: never）')
    p.add_argument('--list-tabs', action='store_true', help='タブ名の一覧を表示して終わる')
    p.add_argument('-q', '--quiet', action='store_true', help='要約を表示しない')
    p.add_argument('--version', action='version', version='nwdiag2cfg ' + __version__)
    return p.parse_args(argv)


def stem_of(path):
    b = os.path.basename(path)
    for ext in ('.drawio.svg', '.drawio.xml', '.drawio', '.svg', '.xml'):
        if b.lower().endswith(ext):
            return b[:-len(ext)]
    return os.path.splitext(b)[0]


def err(msg):
    print('nwdiag2cfg: エラー: ' + msg, file=sys.stderr)
    return 2


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        mx, sha = D.load_mxfile(a.file)
    except (OSError, D.DrawioError) as e:
        return err('入力ファイルを読めません: %s' % e)
    tabs = D.page_names(mx)
    if a.list_tabs:
        for t in tabs:
            print(t)
        return 0
    if not a.tab:
        return err('-t でタブ名を指定してください。タブ: %s' % ' / '.join(tabs))
    for t in [a.tab] + a.aux_tab:
        if t not in tabs:
            return err('タブ「%s」がありません。タブ: %s' % (t, ' / '.join(tabs)))
    try:
        project = load_project(a.project)
    except ProjectError as e:
        return err(str(e))
    prev = {}
    if a.prev_review:
        try:
            prev = R.load_prev_review(a.prev_review)
        except (OSError, ValueError) as e:
            return err('前回のレビューを読めません: %s' % e)

    stem = stem_of(a.file)
    out = a.output or os.path.join('.', stem)
    if os.path.exists(out):
        if not a.force:
            return err('出力先 %s は既にあります。上書きするには --force を付けてください' % out)
        if not os.path.isdir(out):
            return err('出力先 %s はディレクトリではありません' % out)
        shutil.rmtree(out)

    # ---- 読み取り
    page = D.Page(D.page_model(mx, a.tab), a.tab)
    raw = X.classify(page)
    X.classify_edges(raw)
    X.associate_labels(raw)
    X.read_legend(raw)
    X.collect_notes(raw)
    ax = A.merge_aux([A.load_aux(mx, t) for t in a.aux_tab])

    # ---- 中間表現・チェック・生成
    F = Findings(a.tab)
    M = B.build(raw, project, F, ax)
    RT.build_routes(M)
    C.detect_loops(M)
    C.run_checks(M)
    meta = dict(version=__version__, file=os.path.basename(a.file), tab=a.tab, aux=a.aux_tab,
                project=a.project and os.path.basename(a.project), sha256=sha,
                date=datetime.date.today().isoformat(), stem=stem)
    cfgs = render_all(M, meta)
    run_selfcheck(M, cfgs)
    F.finalize()
    for f in F.items:
        old = prev.get(f.key)
        if old:
            f.status = old.get('状態') or f.status
            f.reviewer = old.get('確認者・日付', '')
            f.memo = old.get('メモ', '')
    idmap = {f.key: f.id for f in F.items}
    for c in cfgs.values():
        c.lines = [re.sub(r'\{\{F:([0-9a-f]+)\}\}', lambda m: idmap.get(m.group(1), '?'), ln) for ln in c.lines]

    # ---- 出力
    os.makedirs(os.path.join(out, 'configs'))
    for name, c in cfgs.items():
        _write(os.path.join(out, 'configs', name + '.cfg'), c.text())
    _write(os.path.join(out, 'configs.md'), R.configs_md(M, cfgs, meta))
    _write(os.path.join(out, 'review.md'), R.review_md(M, meta))
    _write(os.path.join(out, 'review.csv'), R.review_csv(M), newline='')
    if a.debug:
        os.makedirs(os.path.join(out, 'debug'))
        _write(os.path.join(out, 'debug', 'model.json'), json.dumps(dump_model(M), ensure_ascii=False, indent=1))
        _write(os.path.join(out, 'debug', 'extract.md'), extract_md(raw))

    n = {s: len([f for f in F.items if f.sev == s]) for s in ('ERROR', 'WARN', 'INFO')}
    if not a.quiet:
        print('%s: コンフィグ %d 台 / 指摘 ERROR %d・WARN %d・INFO %d / TBD %d 箇所' % (
            out, len(cfgs), n['ERROR'], n['WARN'], n['INFO'], len(R.collect_tbd(cfgs))))
    if a.fail_on == 'error' and n['ERROR']:
        return 1
    if a.fail_on == 'warn' and (n['ERROR'] or n['WARN']):
        return 1
    return 0


def _write(path, text, newline=None):
    with open(path, 'w', encoding='utf-8', newline=newline) as f:
        f.write(text)


# ---------------------------------------------------------------- --debug
def dump_model(M):
    segs = []
    for k, s in M.segments.items():
        segs.append(dict(key=list(k), name=s.name, vlan=s.vlan, cidr=s.cidr, cidr_src=getattr(s, 'cidr_src', None),
                         cidr_tbd=getattr(s, 'cidr_tbd', False), aggregate=s.aggregate, vip=s.vip))
    devs = []
    for d in M.devices:
        ports = []
        for p in sorted(d.ports.values(), key=lambda p: B._port_sort(p.name)):
            ports.append(dict(name=p.name, kind=p.kind, po=p.po.name if p.po else None,
                              members=[{'seg': M.segments[k].name if k in M.segments else str(k), 'how': m.how}
                                       for k, m in p.eff_memb().items()],
                              links=[(l.other(p).dev.cfgname + ' ' + l.other(p).name) if l.other(p) else l.ext_name
                                     for l in p.links],
                              l3=p.l3 is not None, shutdown=p.shutdown_reason))
        devs.append(dict(uid=d.uid, name=d.cfgname, cls=d.cls, role=d.role, os=d.os, site=d.site,
                         pair=d.pair.cfgname if d.pair else None, primary=d.primary, ports=ports,
                         l3=[dict(kind=l.kind, seg=M.segments[l.segkey].name if l.segkey in M.segments else None,
                                  vrf=l.vrf, host=l.host, vip=l.vip) for l in d.l3],
                         routes=[str(r) for r in getattr(d, 'routes', [])]))
    return dict(segments=segs, devices=devs, guesses=[dict(g, dev=getattr(g['dev'], 'cfgname', g['dev'])) for g in M.guesses],
                diffs=M.diffs, findings=[dict(id=f.id, sev=f.sev, check=f.check, target=f.target, problem=f.problem,
                                              cells=f.cells, key=f.key) for f in M.F.items])


def extract_md(raw):
    L = ['# 図の読み取り結果（デバッグ用）', '', '## 機器', '']
    for d in raw.devices:
        L.append('- %s: %s' % (d.get('uid'), ' / '.join(str(d.get(k)) for k in ('model', 'cls') if d.get(k))))
    L += ['', '## 線', '']
    for cat, es in sorted(raw.edges.items()):
        L.append('### %s（%d 本）' % (cat, len(es)))
        for e in es:
            a, b = e.get('a'), e.get('b')
            L.append('- %s: %s → %s %s' % (e.get('id'), getattr(a, 'text', '') or getattr(a, 'id', '-'),
                                          getattr(b, 'text', '') or getattr(b, 'id', '-'), ' '.join(e.get('labels', []))))
        L.append('')
    return '\n'.join(L) + '\n'
