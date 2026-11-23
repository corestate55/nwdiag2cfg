"""指摘（レビューシートの1行）と、根拠（設定ブロックごとの説明）。"""
import hashlib

SEV_ORDER = {'ERROR': 0, 'WARN': 1, 'INFO': 2}

# ナレッジ 7章のチェックID（実施結果の一覧に全件出す）
CHECK_IDS = [
    ('N-01', 'ホスト名の重複'), ('N-02', 'ホスト名の命名規則違反'), ('N-03', 'ページ間での名前の違い'),
    ('N-04', 'ラック・フロア名の重複・誤記'), ('N-05', 'ポート名の重複（同一機器内）'),
    ('A-01', 'セグメント間のアドレス重複・包含'), ('A-02', '拠点ブロック外のアドレス'),
    ('A-03', 'バッジのIPがサブネット外・NW/BCアドレス'), ('A-04', '同一セグメントで同じIP'),
    ('A-05', '冗長ペアのIP規則の不一致'), ('A-06', 'バッジの表記揺れ'), ('A-07', '拠点間のラベルの使い回し'),
    ('V-01', 'VLAN ID の重複'), ('V-02', '同じセグメント名で VLAN ID が違う'), ('V-03', 'ラベルの無い横線・横線につながらないラベル'),
    ('V-04', 'リンク両端の VLAN 所属の不一致'), ('V-05', 'VLAN の通り道の断絶'), ('V-06', 'L2 ループ'),
    ('V-07', 'VRRP グループ番号の制約'), ('V-08', 'VLAN の孤立（自己点検）'), ('V-09', '図とコンフィグの VLAN 所属の差分（自己点検）'),
    ('P-01', '線の未接続'), ('P-02', '1つの物理ポートに複数のケーブル'), ('P-03', 'ポート名と線種（速度）の矛盾'),
    ('P-04', '両端のコネクタ・ケーブル種別の不一致'), ('P-05', '機種のポート数・種類との整合'), ('P-06', 'LAG メンバーの対向不一致'),
    ('P-07', 'LAG 番号・メンバー数の両端不一致'), ('P-08', '冗長化の片肺'),
    ('L-01', 'ゲートウェイの無いセグメント'), ('L-02', '冗長ペアの片方にしか SVI/バッジが無い'), ('L-03', '冗長化プロトコルの不一致'),
    ('L-04', 'next-hop が直接接続セグメント上に無い'), ('L-05', '経路の欠落・非対称'), ('L-06', 'VRF 間の到達性'),
    ('L-07', '冗長ペアのセグメントの L2 連続性'),
    ('M-01', '管理IFの無い機器'), ('M-02', '管理経路の単一障害点'), ('M-03', 'OOB とインバンドの混在'), ('M-04', '管理サービスの所在'),
    ('X-01', '合成図と論理構成図のセグメント一致'), ('X-02', '合成図と物理構成図の機器・結線の一致'),
    ('X-03', 'カラー版とモノクロ版のラベル差分'),
    ('D-01', '凡例に無い色・線種'), ('D-02', '線の交差でつながりが曖昧な箇所'), ('D-03', '所属線の色の不一致'),
    ('D-04', '所属線がラベルにつながっている'),
]


class Finding:
    def __init__(self, check, sev, target, problem, basis='', recommend='', provisional='', cells=(), diagram='',
                 page=''):
        self.check = check
        self.sev = sev
        self.target = target
        self.problem = problem
        self.basis = basis
        self.recommend = recommend
        self.provisional = provisional
        self.cells = [c for c in cells if c]
        self.diagram = diagram
        self.page = page
        self.id = None  # R-001...（並べ替えの後で振る）
        self.status = '未確認'
        self.reviewer = ''
        self.memo = ''
        self.refs = []     # (機器名, ポート名 or None) コンフィグに ! WARN を付ける場所

    def attach(self, dev, port=None):
        if (dev, port) not in self.refs:
            self.refs.append((dev, port))
        return self

    @property
    def key(self):
        src = '|'.join([self.check, self.target, ','.join(sorted(self.cells))])
        return hashlib.sha1(src.encode('utf-8')).hexdigest()[:10]

    def cell_text(self, limit=3):
        cs = sorted(set(self.cells))
        if len(cs) <= limit:
            return ', '.join(cs)
        return '%s ほか %d 件' % (', '.join(cs[:limit]), len(cs) - limit)


class Findings:
    def __init__(self, page=''):
        self.items = []
        self.page = page
        self.na = {}       # check id -> 対象外の理由
        self.done = set()  # 実施したチェックID

    def add(self, check, sev, target, problem, **kw):
        kw.setdefault('page', self.page)
        f = Finding(check, sev, target, problem, **kw)
        for g in self.items:  # 同じ指摘は1行に
            if g.key == f.key:
                return g
        self.items.append(f)
        self.done.add(check)
        return f

    def ran(self, *checks):
        self.done.update(checks)

    def not_applicable(self, check, reason):
        self.na[check] = reason

    def finalize(self):
        self.items.sort(key=lambda f: (SEV_ORDER[f.sev], f.check, f.target))
        for i, f in enumerate(self.items, 1):
            f.id = 'R-%03d' % i
        return self.items

    def by_check(self, check):
        return [f for f in self.items if f.check == check]


class Evidence:
    """設定ブロックの根拠（configs.md の根拠表の1行）"""

    def __init__(self, what, reason, labels=('【図】',), cells=(), findings=()):
        self.what = what
        self.reason = reason
        self.labels = list(labels)
        self.cells = [c for c in cells if c]
        self.findings = list(findings)
