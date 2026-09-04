import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from build import build_route_plan, parse, parse_top_level_rules, dedup, serialize_source_rules, derive_groups
from validate_artifacts import expected_provider_names, check
import json
import tempfile

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
        out,_=dedup(ms); self.assertEqual(sum(x.kind=='ip_cidr' for x in out),1); self.assertIn('[80]',[m.value for m in out])
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
    def test_adjacent_cidr_collapsed(self):
        ms=parse('IP-CIDR,1.2.3.0/25','classical','x')+parse('IP-CIDR,1.2.3.128/25','classical','x')
        out,st=dedup(ms); self.assertEqual([m.value for m in out],['1.2.3.0/24']); self.assertEqual(st['ip_collapse_reduction'],1)
    def test_suffix_child_and_modifier_boundaries(self):
        ms=(parse('DOMAIN-SUFFIX,a.example.com','classical','x')+
            parse('DOMAIN-SUFFIX,example.com','classical','x')+
            parse('DOMAIN,a.example.com,no-resolve','classical','x'))
        out,st=dedup(ms)
        self.assertEqual([(m.kind,m.value,m.modifiers) for m in out],[('domain_suffix','example.com',()),('domain','a.example.com',('no-resolve',))])
        self.assertEqual(st['suffix_covered_by_parent_suffix'],1)
    def test_unrelated_suffix_keyword_and_regex_are_not_covered(self):
        ms=(parse('DOMAIN-SUFFIX,example.com','classical','x')+
            parse('DOMAIN-SUFFIX,example.net','classical','x')+
            parse('DOMAIN-KEYWORD,example','classical','x')+
            parse('DOMAIN-REGEX,^example\\.com$','classical','x'))
        out,_=dedup(ms)
        self.assertEqual([(m.kind,m.value) for m in out],[('domain_suffix','example.com'),('domain_suffix','example.net'),('domain_keyword','example'),('domain_regex','^example\\.com$')])
    def test_ipv6_collapse_is_separate_from_ipv4(self):
        ms=parse('IP-CIDR6,2001:db8::/65','classical','x')+parse('IP-CIDR6,2001:db8:0:0:8000::/65','classical','x')
        out,st=dedup(ms)
        self.assertEqual([m.value for m in out],['2001:db8::/64']); self.assertEqual(st['ip_collapse_reduction'],1)
    def test_policy_segments_are_optimized_independently(self):
        left,_=dedup(parse('DOMAIN,api.example.com','classical','left'))
        right,_=dedup(parse('DOMAIN-SUFFIX,example.com','classical','right'))
        self.assertEqual(left[0].kind,'domain'); self.assertEqual(right[0].kind,'domain_suffix')
    def test_destination_and_source_ip_do_not_mix(self):
        ms=parse('IP-CIDR,10.0.0.0/24','classical','x')+parse('SRC-IP-CIDR,10.0.0.0/24','classical','x')
        self.assertEqual(serialize_source_rules(ms),[{'ip_cidr':['10.0.0.0/24']},{'source_ip_cidr':['10.0.0.0/24']}])
    def test_destination_matchers_aggregate_but_port_stays_independent(self):
        ms=(parse('DOMAIN,api.example.com','classical','x')+
            parse('DOMAIN-SUFFIX,example.com','classical','x')+
            parse('IP-CIDR,192.0.2.0/24','classical','x')+
            parse('DST-PORT,443','classical','x'))
        self.assertEqual(serialize_source_rules(ms),[
            {'domain':['api.example.com'],'domain_suffix':['example.com'],'ip_cidr':['192.0.2.0/24']},
            {'port':[443]}])
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

    def test_top_level_route_preserves_custom_policy_and_order(self):
        cfg={'rules':[
            'IP-CIDR,1.12.226.144/32,DIRECT,no-resolve',
            'RULE-SET,A,🤖 AI',
            'DOMAIN-SUFFIX,example.com,My Custom Group',
            'RULE-SET,B,住宅 出口',
            'MATCH,住宅 出口',
        ]}
        plan=build_route_plan(cfg)
        self.assertEqual(plan['consumed'],5)
        self.assertEqual(plan['final'],'住宅 出口')
        self.assertEqual(plan['rules'][0],
            {'ip_cidr':['1.12.226.144/32'],'action':'route','outbound':'direct'},
        )
        self.assertEqual([r['outbound'] for r in plan['rules']], ['direct','🤖 AI','My Custom Group','住宅 出口'])
        self.assertEqual(plan['rules'][2]['domain_suffix'],['example.com'])

    def test_top_level_policy_keywords_and_reject_drop(self):
        cfg={'rules':['DOMAIN,blocked.example,REJECT','DOMAIN,drop.example,REJECT-DROP','MATCH,DIRECT']}
        plan=build_route_plan(cfg)
        self.assertEqual(plan['rules'],[
            {'domain':['blocked.example'],'action':'reject','method':'default'},
            {'domain':['drop.example'],'action':'reject','method':'drop'},
        ])
        self.assertEqual(plan['final'],'direct')

    def test_unsupported_top_level_rule_fails_loudly(self):
        with self.assertRaisesRegex(ValueError, r'rules\[17\]: unsupported top-level rule: GEOIP,CN,DIRECT'):
            parse_top_level_rules({'rules':['DOMAIN,ok.example,DIRECT'] * 17 + ['GEOIP,CN,DIRECT']})

    def test_current_fixture_top_level_fidelity(self):
        import yaml
        cfg=yaml.safe_load((Path(__file__).parents[1] / 'examples' / 'my-rules.yaml').read_text())
        plan=build_route_plan(cfg)
        self.assertEqual(plan['consumed'],len(cfg['rules']))
        self.assertEqual(plan['final'],'⚡ 海外高速')
        routes=plan['rules']
        self.assertEqual([route['ip_cidr'][0] for route in routes[:4]], ['0.0.0.0/32','1.12.226.144/32','195.245.241.114/32','95.169.6.169/32'])
        self.assertEqual(routes[0]['action'],'reject')
        self.assertEqual([route['outbound'] for route in routes if route.get('rule_set') == ['ai']], ['🤖 AI'])
        self.assertEqual([route['outbound'] for route in routes if route.get('rule_set') == ['overseas']], ['⚡ 海外高速'])

    def test_provider_count_follows_consumed_rule_sets(self):
        cfg={'rule-providers': {'A': {}, 'B': {}}, 'rules':['RULE-SET,A,DIRECT','RULE-SET,B,DIRECT']}
        self.assertEqual(expected_provider_names(cfg), {'A','B'})
        cfg['rule-providers'].pop('B')
        cfg['rules'].pop()
        self.assertEqual(expected_provider_names(cfg), {'A'})

    def test_unused_provider_is_not_counted(self):
        cfg={'rule-providers': {'A': {}, 'UNUSED': {}}, 'rules':['RULE-SET,A,DIRECT']}
        self.assertEqual(expected_provider_names(cfg), {'A'})

    def test_missing_artifact_and_audit_fail_with_reason(self):
        cfg={'rule-providers': {'A': {}}, 'rules':['RULE-SET,A,DIRECT']}
        with tempfile.TemporaryDirectory() as td:
            dist=Path(td); (dist/'source').mkdir(); (dist/'srs').mkdir()
            (dist/'report.json').write_text(json.dumps({'providers':1,'groups':1,'unsupported_rules':0}))
            (dist/'semantic-audit.json').write_text(json.dumps({'failed':1,'passed':0,'total':1,'route_order':['direct-pre']}))
            (dist/'memory-benchmark.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'expected 1 source JSON'):
                check(cfg, dist)

    def test_source_srs_tag_mismatch_fails(self):
        cfg={'rule-providers': {'A': {}}, 'rules':['RULE-SET,A,DIRECT']}
        with tempfile.TemporaryDirectory() as td:
            dist=Path(td); (dist/'source').mkdir(); (dist/'srs').mkdir()
            for name, value in [('report.json', {'providers':1,'groups':1,'unsupported_rules':0}), ('semantic-audit.json', {'failed':0,'passed':1,'total':1,'route_order':['direct-pre']}), ('memory-benchmark.json', {'rss_comparable':True,'optimized':{'max_rss':1},'legacy':{'max_rss':2}})]:
                (dist/name).write_text(json.dumps(value))
            (dist/'source'/'direct-pre.json').write_text('{}')
            (dist/'srs'/'wrong.srs').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'missing SRS artifact'):
                check(cfg, dist)

    def test_semantic_audit_failure_is_reported(self):
        cfg={'rule-providers': {'A': {}}, 'rules':['RULE-SET,A,DIRECT']}
        with tempfile.TemporaryDirectory() as td:
            dist=Path(td); (dist/'source').mkdir(); (dist/'srs').mkdir()
            (dist/'source'/'direct-pre.json').write_text('{}')
            (dist/'srs'/'direct-pre.srs').write_bytes(b'placeholder')
            (dist/'report.json').write_text(json.dumps({'providers':1,'groups':1,'unsupported_rules':0,'acceptance':{'source_binary_parity':True,'route_coherence':True}}))
            (dist/'semantic-audit.json').write_text(json.dumps({'failed':2,'passed':3,'total':5,'route_order':['direct-pre']}))
            (dist/'memory-benchmark.json').write_text(json.dumps({'rss_comparable':True,'optimized':{'max_rss':1},'legacy':{'max_rss':2}}))
            with self.assertRaisesRegex(ValueError, 'semantic audit failed: 2/5'):
                check(cfg, dist)

if __name__ == '__main__': unittest.main()
