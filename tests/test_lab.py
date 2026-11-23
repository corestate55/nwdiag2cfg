"""合成図（tests/fixtures/lab.drawio）での一連の動作テスト。python3 -m unittest または pytest で実行する。"""
import csv
import io
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from nwdiag2cfg import extract as X
from nwdiag2cfg.cli import main

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, 'fixtures', 'lab.drawio')


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(list(args))
    return rc, out.getvalue(), err.getvalue()


def block(text, header):
    """'interface Vlan10' などのブロック（次の '!' まで）"""
    m = re.search(r'^%s\n(.*?)^!' % re.escape(header), text, re.M | re.S)
    return m.group(1) if m else None


class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = os.path.join(cls.tmp.name, 'lab')
        cls.rc, cls.stdout, cls.stderr = run('-f', LAB, '-t', '物理・論理', '-o', cls.out, '--debug')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cfg(self, name):
        with open(os.path.join(self.out, 'configs', name + '.cfg'), encoding='utf-8') as f:
            return f.read()

    def test_outputs(self):
        self.assertEqual(self.rc, 0, self.stderr)
        for p in ('review.md', 'review.csv', 'configs.md', 'debug/model.json', 'debug/extract.md'):
            self.assertTrue(os.path.exists(os.path.join(self.out, p)), p)
        self.assertEqual(sorted(os.listdir(os.path.join(self.out, 'configs'))),
                         ['lab-acc01.cfg', 'lab-core01.cfg', 'lab-core02.cfg'])

    def test_svi_and_vrrp(self):
        b = block(self.cfg('lab-core01'), 'interface Vlan10')
        self.assertIn('ip address 192.168.10.1 255.255.255.0', b)
        self.assertIn('address 192.168.10.3 primary', b)
        self.assertIn('priority 110', b)
        b2 = block(self.cfg('lab-core02'), 'interface Vlan10')
        self.assertIn('ip address 192.168.10.2 255.255.255.0', b2)
        self.assertNotIn('priority', b2)

    def test_symmetry_copy(self):
        """lab-core02 は横線を省略しているが、lab-core01 と同じ所属になる（2.10）"""
        b = block(self.cfg('lab-core02'), 'interface TenGigabitEthernet0/1')
        self.assertIn('switchport trunk allowed vlan 9-10', b)

    def test_access_and_gateway(self):
        c = self.cfg('lab-acc01')
        self.assertIn('switchport access vlan 10', block(c, 'interface GigabitEthernet0/3'))
        self.assertIn('ip address 192.168.9.11 255.255.255.0', block(c, 'interface Vlan9'))
        self.assertRegex(c, r'ip default-gateway 192\.168\.9\.3')

    def test_no_error_and_csv(self):
        with open(os.path.join(self.out, 'review.csv'), encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertTrue(rows)
        self.assertFalse([r for r in rows if r['重要度'] == 'ERROR'], rows)
        self.assertTrue(all(r['キー'] for r in rows))

    def test_warn_comment_ids(self):
        """コンフィグの ! WARN は review の ID に置き換わっている"""
        for n in ('lab-core01', 'lab-core02', 'lab-acc01'):
            self.assertNotIn('{{F:', self.cfg(n))

    def test_prev_review_carryover(self):
        src = os.path.join(self.out, 'review.csv')
        with open(src, encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
            cols = list(rows[0].keys())
        rows[0]['状態'] = '対応不要'
        rows[0]['メモ'] = 'テスト'
        prev = os.path.join(self.tmp.name, 'prev.csv')
        with open(prev, 'w', encoding='utf-8-sig', newline='') as f:
            w = csv.DictWriter(f, cols)
            w.writeheader()
            w.writerows(rows)
        out2 = os.path.join(self.tmp.name, 'lab2')
        rc, _, err = run('-f', LAB, '-t', '物理・論理', '-o', out2, '--prev-review', prev, '-q')
        self.assertEqual(rc, 0, err)
        with open(os.path.join(out2, 'review.csv'), encoding='utf-8-sig', newline='') as f:
            got = {r['キー']: r for r in csv.DictReader(f)}
        self.assertEqual(got[rows[0]['キー']]['状態'], '対応不要')
        self.assertEqual(got[rows[0]['キー']]['メモ'], 'テスト')


class CliErrorTest(unittest.TestCase):
    def test_list_tabs(self):
        rc, out, _ = run('-f', LAB, '--list-tabs')
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), '物理・論理')

    def test_unknown_tab(self):
        rc, _, err = run('-f', LAB, '-t', 'ない', '-o', os.devnull)
        self.assertEqual(rc, 2)
        self.assertIn('タブ', err)

    def test_existing_output_needs_force(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = run('-f', LAB, '-t', '物理・論理', '-o', d)
            self.assertEqual(rc, 2)
            self.assertIn('--force', err)
            rc, _, err = run('-f', LAB, '-t', '物理・論理', '-o', d, '--force', '-q')
            self.assertEqual(rc, 0, err)

    def test_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, _ = run('-f', LAB, '-t', '物理・論理', '-o', os.path.join(d, 'x'), '-q', '--fail-on', 'warn')
            self.assertEqual(rc, 1)
            rc, _, _ = run('-f', LAB, '-t', '物理・論理', '-o', os.path.join(d, 'y'), '-q', '--fail-on', 'error')
            self.assertEqual(rc, 0)


class SegLabelTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(X.parse_seglabel('172.17.0.0/27EXT, VLAN2')['name'], 'EXT')
        r = X.parse_seglabel('172.18.64.0/18OFFICE_Fn, VLAN300-399')
        self.assertEqual((r['name'], r['vlan'], r['cidr']), ('OFFICE_Fn', (300, 399), '172.18.64.0/18'))
        r = X.parse_seglabel('VLAN90 (出向者向け/N社NW)')
        self.assertEqual((r['name'], r['note']), ('VLAN90', '出向者向け/N社NW'))
        r = X.parse_seglabel('x.x.x.x / NGT-INET')
        self.assertEqual((r['name'], r['cidr']), ('NGT-INET', None))
        self.assertEqual(X.parse_seglabel('VLAN9')['name'], '')


if __name__ == '__main__':
    unittest.main()
