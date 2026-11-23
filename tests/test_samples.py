"""実際の図（書籍・セミナー資料）での回帰テスト。ファイルが無い環境ではスキップする。

ファイルの場所は環境変数で変えられる:
  NWDIAG2CFG_BOOK=.../diagrams.drawio.svg
  NWDIAG2CFG_SEMINAR=.../演習作例_実践編2.drawio.svg
"""
import os
import re
import tempfile
import unittest

from .test_lab import run, block

BOOK = os.environ.get('NWDIAG2CFG_BOOK', '/mnt/project-files/nwdiagbook/diagrams.drawio.svg')
SEMINAR = os.environ.get('NWDIAG2CFG_SEMINAR', '/mnt/project-files/additional_diagrams/演習作例_実践編2.drawio.svg')


def read(out, name):
    with open(os.path.join(out, 'configs', name + '.cfg'), encoding='utf-8') as f:
        return f.read()


@unittest.skipUnless(os.path.exists(BOOK), 'diagrams.drawio.svg が無い')
class Book4CTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = os.path.join(cls.tmp.name, 'o')
        cls.rc, _, cls.err = run('-f', BOOK, '-t', '物理・論理合成図_4C', '--aux-tab', '論理構成図_4C', '-o', cls.out, '-q')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_devices(self):
        self.assertEqual(self.rc, 0, self.err)
        self.assertEqual(len(os.listdir(os.path.join(self.out, 'configs'))), 18)

    def test_os1_po1(self):
        """未接続線 -119 は EXT↔GRT の線。Po1 に VLAN2 は入らない（基準トライアルの誤りの修正）"""
        b = block(read(self.out, 'os1-core01'), 'interface Port-channel1')
        self.assertIn('switchport trunk allowed vlan 9-11,300-399', b)

    def test_mgmt_from_logical_page(self):
        b = block(read(self.out, 'os1-core01'), 'interface Vlan9')
        self.assertIn('ip address 172.18.1.1 255.255.255.0', b)

    def test_routes(self):
        c = read(self.out, 'os1-core01')
        self.assertIn('ip route 0.0.0.0 0.0.0.0 172.18.0.1', c)
        self.assertIn('ip route 172.17.0.0 255.255.0.0 172.18.0.2', c)

    def test_known_findings(self):
        with open(os.path.join(self.out, 'review.md'), encoding='utf-8') as f:
            md = f.read()
        self.assertRegex(md, r'A-01 \| [^|]+\| os1 MGMT ⇔ tk1 DMZ')
        self.assertIn('os1-core02 Gi0/1', md)          # Te0/5 の誤記（P-03）
        self.assertRegex(md, r'N-01 \| [^|]+\| tk1-fnacc01 ')


@unittest.skipUnless(os.path.exists(SEMINAR), '演習作例_実践編2.drawio.svg が無い')
class SeminarTest(unittest.TestCase):
    def test_nagoya(self):
        with tempfile.TemporaryDirectory() as d:
            for tab in ('物理・論理', '物理・論理(発展)'):
                out = os.path.join(d, re.sub(r'\W', '_', tab))
                rc, _, err = run('-f', SEMINAR, '-t', tab, '-o', out, '-q')
                self.assertEqual(rc, 0, err)
                fw = read(out, 'ngt1-fw01')
                self.assertIn('nameif outside', fw)
                self.assertIn('tunnel source interface outside', fw)
                core = read(out, 'ngt1-core01')
                self.assertIn('vrf definition N-corp', core)
                self.assertIn('interface Vlan90', core)


if __name__ == '__main__':
    unittest.main()
