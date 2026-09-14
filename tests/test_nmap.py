from pathlib import Path
import tempfile
import unittest
from app import command,parse_xml,compare

class NmapTests(unittest.TestCase):
    def test_localhost(self):self.assertIn('-sT',command('quick','127.0.0.1'))
    def test_scope(self):
        with self.assertRaises(ValueError):command('quick','192.168.0.0/16',True)
    def test_authorization(self):
        with self.assertRaises(ValueError):command('quick','192.168.1.1')
    def test_xml(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'scan.xml';p.write_text('<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>')
            r=parse_xml(p);self.assertEqual(r['127.0.0.1']['ports']['tcp/80']['state'],'open');self.assertEqual(compare({},r)['changes'][0]['event'],'NEW_HOST')
