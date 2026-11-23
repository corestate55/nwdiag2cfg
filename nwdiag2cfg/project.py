"""プロジェクト既定値ファイル（TOML）の読込と、ナレッジ v1.1 の既定値。

未指定の項目はナレッジの既定値を使い、configs.md の「既定値を使った項目」に一覧で出す。
"""
import fnmatch

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None

# (キー, ナレッジ既定値, ナレッジの参照箇所, 説明)
DEFAULTS = [
    ('lag_mode', 'active', '1.1 / R5 / 6.2', 'LAG モード（active=LACP, on=static）'),
    ('fhrp_protocol', 'legend', '1.1 / 2.7', '冗長化プロトコル（legend=凡例の表記、vrrp、hsrp）'),
    ('fhrp_format', 'vrrpv3', '1.1 / 10.1', 'VRRP の書式（vrrpv3、legacy=旧 IOS 書式）'),
    ('fhrp_priority_primary', 110, '1.1 / 6.2', '01号機の優先度'),
    ('fhrp_preempt', True, '1.1 / 6.2', 'プリエンプト'),
    ('fhrp_group', 'vlan_id', '6.2', 'グループ番号の規則（vlan_id）'),
    ('mgmt_vrf_name', 'mgmt', '1.1 / R12', '管理 VRF の名前（図に vrf 箱が無い場合）'),
    ('trunk_extra', [], '1.1 / 10.1', 'trunk に付ける追加コマンド'),
    ('pair_output', 'full', '1.1 / 8.1', '冗長ペアの02号機の出力形式（full のみ対応）'),
    ('router_same_segment', 'switchport_svi', '1.1 / 4.2', 'ルーターで同一セグメント2ポートの実装（switchport_svi / bdi_evc）'),
    ('unused_ports', 'none', '1.1 / 6.2', '未使用ポートの扱い（none=設定しない、shutdown）'),
    ('stp_mode', 'rapid-pvst', '6.2', 'STP モード（冗長経路がある場合）'),
    ('dangling_distance', 10, '6.5（本ツール D9）', '未接続線の端点と接続先候補の距離しきい値（px）'),
]


class ProjectError(Exception):
    pass


class Project:
    def __init__(self, data=None, path=None):
        self.path = path
        self.data = data or {}
        d = self.data.get('defaults', {}) or {}
        self.values = {}
        self.used_default = []
        for key, val, ref, desc in DEFAULTS:
            if key in d:
                self.values[key] = d[key]
            else:
                self.values[key] = val
        self.platform = self.data.get('platform', {}) or {}
        self.sites = self.data.get('sites', {}) or {}
        self.aggregates = self.data.get('aggregates', {}) or {}
        self.routes = self.data.get('routes', []) or []
        self.ipam = self.data.get('ipam', {}) or {}
        self.services = self.data.get('services', {}) or {}
        self.overrides = self.data.get('overrides', {}) or {}

    def get(self, key):
        return self.values[key]

    def specified(self, key):
        return key in (self.data.get('defaults', {}) or {})

    def note_default(self, key, devices):
        """既定値を使った項目として記録（未指定のときだけ）"""
        if self.specified(key):
            return
        for k, val, ref, desc in DEFAULTS:
            if k == key:
                for u in self.used_default:
                    if u['key'] == key:
                        u['devices'].update(devices)
                        return
                self.used_default.append(dict(key=key, value=val, ref=ref, desc=desc, devices=set(devices)))
                return

    def platform_for(self, name):
        for pat, os_ in self.platform.items():
            if fnmatch.fnmatch(name, pat):
                return os_
        return None

    def ipam_for(self, device, segment_name):
        return self.ipam.get('%s:%s' % (device, segment_name))


def load_project(path):
    if not path:
        return Project()
    if tomllib is None:
        raise ProjectError('既定値ファイル（TOML）の読込には Python 3.11 以上が必要です')
    try:
        with open(path, 'rb') as f:
            data = tomllib.load(f)
    except OSError as e:
        raise ProjectError('既定値ファイルを読めません: %s (%s)' % (path, e))
    except tomllib.TOMLDecodeError as e:
        raise ProjectError('既定値ファイルの書式エラー: %s (%s)' % (path, e))
    return Project(data, path)
