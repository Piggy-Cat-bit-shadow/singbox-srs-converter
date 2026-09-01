import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from build import parse, dedup, serialize_source_rules, derive_groups

class BuildTests(unittest.TestCase):
    def test_domain_types(self):
        self.assertEqual(parse('DOMAIN,WWW.Example.com','classical','x')[0].value,'www.example.com')
        self.assertEqual(parse('DOMAIN-SUFFIX,.Example.com','classical','x')[0].kind,'domain_suffix')
        self.assertEqual(parse('DOMAIN-WILDCARD,clients*.google.com','classical','x')[0].value,'(?i)^clients.*\\.google\\.com$')
        self.assertEqual(parse('DOMAIN-REGEX,^a,b$','classical','x')[0].value,'^a,b$')
    def test_safe_domain_dedup(self):
        ms=parse('DOMAIN,api.example.com','classical','x')+parse('DOMAIN-SUFFIX,example.com','classical','x')+parse('DOMAIN-KEYWORD,example','classical','x')
        out,st=dedup(ms); self.assertEqual([x.kind for x in out],['domain','domain_suffix','domain_keyword']); self.assertEqual(st['domain_covered_by_suffix'],0)
    def test_cidr_and_ports(self):
        ms=parse('IP-CIDR,10.0.0.0/8','classical','x')+parse('IP-CIDR,10.1.0.0/16','classical','x')+parse('DST-PORT,80/100-200','classical','x')
        out,_=dedup(ms); self.assertEqual(sum(x.kind=='ip_cidr' for x in out),2); self.assertEqual(out[-2].value,'[80]')
    def test_process_or(self):
        self.assertEqual(parse('PROCESS-NAME,org.telegram.messenger','classical','x')[0].kind,'process_name')
    def test_unsupported(self):
        with self.assertRaises(ValueError): parse('GEOIP,CN','classical','x')
    def test_domain_provider_wildcards(self):
        import re
        one=re.compile(parse('*.example.com','domain','x')[0].value)
        self.assertTrue(one.match('a.example.com')); self.assertFalse(one.match('a.b.example.com'))
        suffix=parse('+.example.com','domain','x')[0]
        self.assertEqual(suffix.kind,'domain_suffix'); self.assertEqual(suffix.value,'example.com')
        child=re.compile(parse('.example.com','domain','x')[0].value)
        self.assertFalse(child.match('example.com')); self.assertTrue(child.match('a.example.com'))
    def test_adjacent_cidr_not_collapsed(self):
        ms=parse('IP-CIDR,1.2.3.0/25','classical','x')+parse('IP-CIDR,1.2.3.128/25','classical','x')
        out,_=dedup(ms); self.assertEqual([m.value for m in out],['1.2.3.0/25','1.2.3.128/25'])
    def test_process_is_two_or_rules_in_source_shape(self):
        m=parse('PROCESS-NAME,test','classical','x')[0]
        self.assertEqual(m.kind,'process_name')
        self.assertEqual(serialize_source_rules([m]),[{'process_name':['test']}])
    def test_source_rule_boundaries_are_not_and_merged(self):
        ms=(parse('DOMAIN-SUFFIX,example.com','classical','x')+
            parse('DST-PORT,443','classical','x')+
            parse('NETWORK,udp','classical','x'))
        self.assertEqual(serialize_source_rules(ms),[
            {'domain_suffix':['example.com']},{'port':[443]},{'network':['udp']}])
    def test_groups_come_from_rules_order(self):
        cfg={'rules':['RULE-SET,A,DIRECT','RULE-SET,B,DIRECT','RULE-SET,C,🤖 AI','RULE-SET,D,DIRECT','RULE-SET,E,⚡ 海外高速','RULE-SET,F,REJECT-DROP','RULE-SET,G,DIRECT','RULE-SET,H,DIRECT,no-resolve']}
        self.assertEqual([g['providers'] for g in derive_groups(cfg)], [['A','B'],['C'],['D'],['E'],['F'],['G'],['H']])

if __name__ == '__main__': unittest.main()
