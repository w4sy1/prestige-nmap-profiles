import unittest
from app import command


class HostnameTests(unittest.TestCase):
    def test_authorization_and_syntax(self):
        with self.assertRaises(ValueError):command('quick','router.example')
        self.assertEqual(command('quick','router.example',True)[-1],'router.example')
        for value in ('-sV','host;whoami','host/path','host && id'):
            with self.assertRaises(ValueError):command('quick',value,True)

    def test_ipv6_and_localhost(self):
        self.assertIn('-6',command('quick','::1'))
        self.assertEqual(command('localhost-audit','localhost')[-1],'127.0.0.1')
