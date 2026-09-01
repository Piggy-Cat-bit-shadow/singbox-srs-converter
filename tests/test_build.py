import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from build import parse, dedup

class BuildTests(unittest.TestCase):
    def test_domain_types(self):
        self.assertEqual(parse('DOMAIN,WWW.Example.com','classical','x')[0].value,'www.example.com')
        self.assertEqual(parse('DOMAIN-SUFFIX,.Example.com','classical','x')[0].kind,'domain_suffix')
        self.assertEqual(parse('DOMAIN-WILDCARD,clients*.google.com','classical','x')[0].value,'(?i)^clients.*\\.google\\.com$')
        self.assertEqual(parse('DOMAIN-REGEX,^a,b$','classical','x')[0].value,'^a,b$')
    def test_safe_domain_dedup(self):
        ms=parse('DOMAIN,api.example.com','classical','x')+parse('DOMAIN-SUFFIX,example.com','classical','x')+parse('DOMAIN-KEYWORD,example','classical','x')
        out,st=dedup(ms); self.assertEqual([x.kind for x in out],['domain_suffix','domain_keyword']); self.assertEqual(st['domain_covered_by_suffix'],1)
    def test_cidr_and_ports(self):
        ms=parse('IP-CIDR,10.0.0.0/8','classical','x')+parse('IP-CIDR,10.1.0.0/16','classical','x')+parse('DST-PORT,80/100-200','classical','x')
        out,_=dedup(ms); self.assertEqual(sum(x.kind=='ip_cidr' for x in out),1); self.assertEqual(out[-2].value,'[80]')
    def test_process_or(self):
        self.assertEqual(parse('PROCESS-NAME,org.telegram.messenger','classical','x')[0].kind,'process_name')
    def test_unsupported(self):
        with self.assertRaises(ValueError): parse('GEOIP,CN','classical','x')

if __name__ == '__main__': unittest.main()
