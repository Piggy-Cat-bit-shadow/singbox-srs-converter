#!/usr/bin/env python3
import argparse, csv, gzip, hashlib, ipaddress, io, json, re, shutil, subprocess, tempfile, urllib.request, ssl, time, yaml
from http.client import IncompleteRead
import certifi
from dataclasses import dataclass
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
# Compatibility names for the current seven positional policy segments.  Provider
# membership and ordering are always derived from the input rules list.
SEGMENT_TAGS={('DIRECT',(),1):'direct-pre',('🤖 AI',(),1):'ai',('DIRECT',(),2):'direct-middle',('⚡ 海外高速',(),1):'overseas',('REJECT-DROP',(),1):'ads',('DIRECT',(),3):'direct-cn',('DIRECT',('no-resolve',),1):'direct-cn-ip'}
POLICY_OUTBOUNDS={'DIRECT':'direct','🤖 AI':'ai','⚡ 海外高速':'overseas'}
SAMPLES={k:[] for k in ('exact_duplicates_removed','domain_covered_by_suffix','suffix_covered_by_parent_suffix','ipcidr_duplicates_removed','ipcidr_covered_by_parent')}
@dataclass(frozen=True)
class M:
    kind:str; value:str; modifiers:tuple=(); provider:str=''; source:str=''; expanded_from:str|None=None

def derive_groups(cfg):
    """Derive contiguous RULE-SET segments directly from the sole input SoT."""
    groups=[]; current=None; counts={}
    for index, raw in enumerate(cfg.get('rules',[])):
        parts=str(raw).split(',')
        if parts[0].upper()!='RULE-SET':
            current=None
            continue
        if len(parts)<3: raise ValueError(f'rules[{index}]: malformed RULE-SET: {raw}')
        provider,policy=parts[1],parts[2]; modifiers=tuple(parts[3:])
        if any(x not in ('no-resolve',) for x in modifiers): raise ValueError(f'rules[{index}]: unsupported RULE-SET modifier: {raw}')
        key=(policy,modifiers)
        if current is None or current['_key']!=key:
            ordinal=counts.get(key,0)+1; counts[key]=ordinal
            tag=SEGMENT_TAGS.get((policy,modifiers,ordinal))
            if tag is None: raise ValueError(f'rules[{index}]: no stable public tag for segment {key} #{ordinal}')
            current={'tag':tag,'policy':policy,'modifiers':list(modifiers),'providers':[],'_key':key,'top_level_index':index}
            groups.append(current)
        current['providers'].append(provider)
    for g in groups: g.pop('_key')
    if not groups: raise ValueError('rules: no RULE-SET segments')
    return groups

def norm(v):
    v=v.strip().lower().rstrip('.')
    if not v: raise ValueError('empty domain')
    return v
def wildcard(v, labels=False):
    if not v: raise ValueError('empty wildcard')
    out='';
    for c in v:
        out += '.*' if c=='*' and not labels else ('[^.]+' if c=='*' else ('.' if c=='?' else re.escape(c)))
    return '(?i)^'+out+'$'
def ports(v):
    one=[]; ranges=[]
    for x in v.split('/'):
        if '-' in x:
            a,b=x.split('-',1); a=int(a); b=int(b)
            if not (0<=a<=b<=65535): raise ValueError('invalid port range')
            ranges.append(f'{a}:{b}')
        else:
            n=int(x)
            if not 0<=n<=65535: raise ValueError('invalid port')
            one.append(n)
    return one,ranges
def parse(raw, behavior, provider):
    raw=raw.strip()
    if behavior=='ipcidr':
        net=ipaddress.ip_network(raw, strict=False); return [M('ip_cidr',str(net),provider=provider,source=raw)]
    if behavior=='domain' and ',' not in raw:
        if raw.startswith('+.'): return [M('domain_suffix',norm(raw[2:]),provider=provider,source=raw)]
        if raw.startswith('.'):
            return [M('domain_regex',wildcard(raw[1:],False).replace('^','(?i)^.+\\.',1),provider=provider,source=raw)]
        if '+' in raw: raise ValueError('invalid + wildcard')
        return [M('domain_regex',wildcard(raw,True),provider=provider,source=raw)] if '*' in raw or '?' in raw else [M('domain',norm(raw),provider=provider,source=raw)]
    if ',' in raw:
        kind, rest=raw.split(',',1); parts=rest.split(','); mods=[]
        while parts and parts[-1] in ('no-resolve','src'): mods.insert(0,parts.pop())
        if any(x not in ('no-resolve','src') for x in mods): raise ValueError('unknown modifier')
        value=','.join(parts).strip(); source=raw
    else: kind=value=raw; mods=[]; source=raw
    kind=kind.upper(); mods=tuple(mods)
    if kind in ('DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD'): return [M({'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword'}[kind],norm(value),mods,provider,source)]
    if kind=='DOMAIN-REGEX': return [M('domain_regex',value,mods,provider,source)]
    if kind=='DOMAIN-WILDCARD': return [M('domain_regex',wildcard(value),mods,provider,source)]
    if kind in ('IP-CIDR','IP-CIDR6','SRC-IP-CIDR'):
        net=str(ipaddress.ip_network(value,strict=False)); return [M('source_ip_cidr' if kind=='SRC-IP-CIDR' else 'ip_cidr',net,mods,provider,source)]
    if kind in ('DST-PORT','SRC-PORT'):
        a,b=ports(value); return [M(('source_' if kind=='SRC-PORT' else '')+'port',json.dumps(a),mods,provider,source), M(('source_' if kind=='SRC-PORT' else '')+'port_range',json.dumps(b),mods,provider,source)]
    if kind=='NETWORK' and value in ('tcp','udp'): return [M('network',value,mods,provider,source)]
    if kind in ('PROCESS-NAME','PROCESS-PATH','PROCESS-PATH-REGEX'):
        return [M({'PROCESS-NAME':'process_name','PROCESS-PATH':'process_path','PROCESS-PATH-REGEX':'process_path_regex'}[kind],value,mods,provider,source)]
    if kind=='IP-ASN': return [M('asn',str(int(value)),mods,provider,source)]
    if kind=='SRC-IP-ASN': return [M('src_asn',str(int(value)),mods,provider,source)]
    raise ValueError(f'unsupported kind {kind}')
def download_url(url):
    """Download in-memory with Range resume; upstreams occasionally truncate."""
    ctx=ssl.create_default_context(cafile=certifi.where()); data=bytearray(); expected=None
    for attempt in range(100):
        headers={'User-Agent':'singbox-srs-converter'}
        if data: headers['Range']=f'bytes={len(data)}-'
        try:
            response=urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60,context=ctx)
            if data and response.status != 206: raise RuntimeError('server ignored HTTP Range resume')
            length=response.headers.get('Content-Length')
            if length: expected=len(data)+int(length)
            data.extend(response.read())
            if expected is None or len(data)>=expected: return bytes(data)
        except IncompleteRead as e: data.extend(e.partial)
        except Exception:
            if attempt==99: raise
        time.sleep(0.25)
    raise RuntimeError('incomplete download after resume attempts')
def load(pname,spec,base):
    if spec['type']=='file': data=(ROOT/spec['path']).read_bytes()
    else:
        try: data=download_url(spec['url'])
        except Exception as e: raise RuntimeError(f'{pname}: download failed: {e}') from e
    sha=hashlib.sha256(data).hexdigest(); fmt=spec.get('format','yaml'); text=data.decode('utf-8-sig')
    if fmt=='text': vals=[x for x in text.splitlines() if x.strip() and not x.startswith('#')]
    else:
        obj=yaml.safe_load(text); vals=obj if isinstance(obj,list) else obj.get('payload',obj.get('rules')) if isinstance(obj,dict) else None
        if not isinstance(vals,list): raise ValueError('invalid YAML provider structure')
    ms=[]
    for raw in vals: ms += parse(str(raw),spec['behavior'],pname)
    return ms,sha,len(vals)
def dedup(ms):
    """Conservative, policy-local exact dedup only.

    Coverage inference is deliberately disabled: matching set equivalence alone is
    insufficient once provenance and future metadata are considered.
    """
    stats={k:0 for k in SAMPLES}; seen=set(); unique=[]
    for m in ms:
        key=(m.kind,m.value,m.modifiers)
        if key in seen: stats['exact_duplicates_removed']+=1
        else: seen.add(key); unique.append(m)
    return unique,stats
def expand_asn(allms):
    need={m.value for ms in allms.values() for m in ms if m.kind in ('asn','src_asn')}
    if not need: return allms, {}
    ctx=ssl.create_default_context(cafile=certifi.where()); meta=json.loads(urllib.request.urlopen('https://api.github.com/repos/FyraLabs/geolite2/releases/latest',context=ctx).read())
    assets={x['name']:x['browser_download_url'] for x in meta['assets']}; result={k:[] for k in need}; audit={'release':meta['tag_name'],'prefixes':{}}
    for name,url in assets.items():
        if not name.endswith('.csv') or 'GeoLite2-ASN-Blocks-' not in name: continue
        raw=download_url(url); count=0
        for row in csv.DictReader(io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')):
            if row.get('autonomous_system_number') in need:
                result[row['autonomous_system_number']].append((row['network'], 'v4' if ':' not in row['network'] else 'v6')); count+=1
        audit['prefixes'][name]=count
    for n in need:
        if not result[n]: raise ValueError(f'ASN {n} has no GeoLite2 prefix')
    for name,ms in allms.items():
        out=[]
        for m in ms:
            if m.kind in ('asn','src_asn'):
                for net,_ in result[m.value]: out.append(M('source_ip_cidr' if m.kind=='src_asn' else 'ip_cidr',str(ipaddress.ip_network(net,strict=False)),m.modifiers,m.provider,m.source,m.source))
            else: out.append(m)
        allms[name]=out
    return allms,audit
def serialize_source_rules(matchers):
    """Keep each original classical rule as a separate headless rule.

    A single raw port expression may contain both exact ports and ranges, which
    share a rule boundary and can safely occupy one default rule.
    """
    grouped={}; order=[]
    for m in matchers:
        key=(m.provider,m.source,m.modifiers)
        if key not in grouped: grouped[key]=[]; order.append(key)
        grouped[key].append(m)
    rules=[]
    for key in order:
        fields={}
        for m in grouped[key]:
            if m.kind in ('asn','src_asn'): raise ValueError(f'ASN expansion failed: {m.source}')
            if m.kind in ('port','port_range','source_port','source_port_range'):
                fields.setdefault(m.kind,[]).extend(json.loads(m.value))
            else: fields.setdefault(m.kind,[]).append(m.value)
        rules.append({k:list(dict.fromkeys(v)) for k,v in fields.items() if v})
    return rules
def semantic_audit(rule_dir, sb, groups, fmt='binary'):
    corpus=[
      ('youtube.com','overseas'),('www.youtube.com','overseas'),('music.youtube.com','overseas'),('ads.youtube.com','overseas'),
      ('youtubei.googleapis.com','overseas'),('youtube.googleapis.com','overseas'),('googlevideo.com','overseas'),('r1---sn.googlevideo.com','overseas'),
      ('ytimg.com','overseas'),('i.ytimg.com','overseas'),('ggpht.com','overseas'),('yt3.ggpht.com','overseas'),
      ('chat.openai.com','ai'),('api.telegram.org','overseas'),('github.com','overseas'),('icloud.com','direct-middle'),('wechat.com','direct-middle'),('douyin.com','direct-cn'),
      ('000dn.com','ads'),('001union.com','ads'),('002777.xyz','ads')]
    audit=[]
    for domain, expected in corpus:
        hits=[]
        for g in groups:
            suffix='.srs' if fmt=='binary' else '.json'
            p=subprocess.run([sb,'rule-set','match','-f',fmt,str(rule_dir/f'{g["tag"]}{suffix}'),domain],capture_output=True,text=True)
            if p.returncode==0 and p.stderr.startswith('match '): hits.append(g['tag'])
        actual=hits[0] if hits else None
        audit.append({'domain':domain,'expected':expected,'matched_groups':hits,'first_match':actual,'passed':actual==expected})
    return audit
def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('input'); ap.add_argument('--base-url',default='https://raw.githubusercontent.com/Piggy-Cat-bit-shadow/singbox-srs-converter/main'); ap.add_argument('--sing-box',default='sing-box'); a=ap.parse_args()
    cfg=yaml.safe_load(Path(a.input).read_text()); providers=cfg['rule-providers']; groups=derive_groups(cfg); names=[p for g in groups for p in g['providers']]
    if len(names)!=len(set(names)) or set(names)!=set(providers): raise SystemExit('provider/rules mismatch: every provider must be used exactly once')
    tmp=Path(tempfile.mkdtemp(prefix='srs-build-',dir=ROOT)); (tmp/'source').mkdir(); (tmp/'srs').mkdir(); (tmp/'generated').mkdir(); details={}; allms={}; stats={k:0 for k in SAMPLES}
    try:
        for n,s in providers.items():
            ms,sha,raw=load(n,s,ROOT); allms[n]=ms; details[n]={'raw_count':raw,'parsed_count':len(ms),'sha256':sha,'source':s.get('url',s.get('path'))}
        asn_rules=sum(1 for ms in allms.values() for m in ms if m.kind in ('asn','src_asn'))
        allms,asn_audit=expand_asn(allms)
        group_details={}; before_total=after_total=0; coverage={}; compile_count=decompile_count=0
        for g in groups:
            ms=[m for n in g['providers'] for m in allms[n]]; before=len(ms); clean,st=dedup(ms)
            before_total += before; after_total += len(clean)
            for k,v in st.items(): stats[k]+=v
            rules=serialize_source_rules(clean)
            if not rules: raise ValueError(f'empty group {g["tag"]}')
            (tmp/'source'/f'{g["tag"]}.json').write_text(json.dumps({'version':2,'rules':rules},ensure_ascii=False,separators=(',',':')),encoding='utf-8')
            subprocess.run([a.sing_box,'rule-set','compile','--output',str(tmp/'srs'/f'{g["tag"]}.srs'),str(tmp/'source'/f'{g["tag"]}.json')],check=True)
            compile_count+=1
            decompiled=tmp/f"decompiled-{g['tag']}.json"
            subprocess.run([a.sing_box,'rule-set','decompile',str(tmp/'srs'/f'{g["tag"]}.srs'),'-o',str(decompiled)],check=True)
            json.loads(decompiled.read_text(encoding='utf-8'))
            decompiled.unlink()
            decompile_count+=1
            group_details[g['tag']]={'provider_count':len(g['providers']),'raw_rules':sum(details[n]['raw_count'] for n in g['providers']),'before_dedup':before,'after_dedup':len(clean),'removed':before-len(clean),'srs_bytes':(tmp/'srs'/f'{g["tag"]}.srs').stat().st_size}
            for provider in g['providers']:
                survivors=[m for m in clean if m.provider==provider]
                coverage[provider]={'group':g['tag'],'raw_rules':details[provider]['raw_count'],'converted_matchers':len(allms[provider]),'headless_rules':len(serialize_source_rules(survivors))}
                if not survivors: raise ValueError(f'provider lost after exact dedup: {provider}')
        route={'route':{'rule_set':[{'type':'remote','tag':g['tag'],'format':'binary','url':a.base_url.rstrip('/')+'/dist/srs/'+g['tag']+'.srs','update_interval':'1d'} for g in groups],'rules':[{'ip_cidr':['0.0.0.0/32'],'action':'reject','method':'default'}]+[({'rule_set':[g['tag']],'action':'reject','method':'drop'} if g['policy']=='REJECT-DROP' else {'rule_set':[g['tag']],'action':'route','outbound':POLICY_OUTBOUNDS[g['policy']]}) for g in groups],'final':'overseas'}}
        (tmp/'generated'/'sing-box-route.json').write_text(json.dumps(route,ensure_ascii=False,indent=2)+'\n')
        semantic=semantic_audit(tmp/'srs',a.sing_box,groups)
        source_semantic=semantic_audit(tmp/'source',a.sing_box,groups,'source')
        if [x['first_match'] for x in semantic] != [x['first_match'] for x in source_semantic]: raise RuntimeError('source/binary semantic parity failed')
        failed=[x for x in semantic if not x['passed']]
        audit_payload={'version':1,'route_order':[g['tag'] for g in groups],'total':len(semantic),'passed':len(semantic)-len(failed),'failed':len(failed),'cases':semantic}
        (tmp/'semantic-audit.json').write_text(json.dumps(audit_payload,ensure_ascii=False,indent=2)+'\n')
        if failed: raise RuntimeError('semantic regression failed: '+json.dumps(failed,ensure_ascii=False))
        route_tags=[r['rule_set'][0] for r in route['route']['rules'][1:]]
        expected_tags=[g['tag'] for g in groups]
        if route_tags != expected_tags: raise RuntimeError('route order does not match derived segments')
        source_tags={p.stem for p in (tmp/'source').glob('*.json')}; srs_tags={p.stem for p in (tmp/'srs').glob('*.srs')}
        if source_tags != set(expected_tags) or srs_tags != set(expected_tags): raise RuntimeError('source/SRS tags do not match route')
        acceptance={'version':1,'input_sha256':sha256_file(Path(a.input)),'provider_coverage':coverage,'providers_included':len(coverage),'providers_total':len(providers),'segments':len(groups),'srs_compile':{'passed':compile_count,'total':len(groups)},'srs_decompile':{'passed':decompile_count,'total':len(groups)},'semantic_regression':{'passed':audit_payload['passed'],'total':audit_payload['total'],'failed':audit_payload['failed']},'source_binary_parity':True,'route_coherence':True,'source_sha256':{p.stem:sha256_file(p) for p in (tmp/'source').glob('*.json')},'srs_sha256':{p.stem:sha256_file(p) for p in (tmp/'srs').glob('*.srs')},'route_sha256':sha256_file(tmp/'generated'/'sing-box-route.json')}
        (tmp/'acceptance.json').write_text(json.dumps(acceptance,ensure_ascii=False,indent=2)+'\n')
        status='# Build Status: PASS\n\nInput: examples/my-rules.yaml\n\nProviders: {}/{} included\nSegments: {}/{}\nSRS compile: {}/{} PASS\nSRS decompile: {}/{} PASS\nProvider coverage: {}/{} PASS\nSemantic regression: {}/{} PASS\nSource/Binary parity: PASS\nRoute order: PASS\nUnsupported rules: 0\n\nResult:\nAll generated rule sets passed acceptance checks.\n'.format(len(coverage),len(providers),len(groups),len(groups),compile_count,len(groups),decompile_count,len(groups),len(coverage),len(providers),audit_payload['passed'],audit_payload['total'])
        (tmp/'STATUS.md').write_text(status)
        removed=before_total-after_total
        if removed != sum(stats.values()): raise ValueError('dedup accounting mismatch')
        report={'version':1,'sing_box_version':subprocess.run([a.sing_box,'version'],capture_output=True,text=True).stdout.strip(),'providers':len(providers),'groups':len(groups),'segments':groups,'raw_rules':sum(x['raw_count'] for x in details.values()),'mapped_original_rules':sum(x['parsed_count'] for x in details.values()),'unsupported_rules':0,'semantic_limitations':['Mihomo no-resolve has no SRS field; preserved in IR/provenance and no resolve action is inserted.'],'asn_rules':asn_rules,'asn_expanded_prefixes':sum(v for v in asn_audit.get('prefixes',{}).values()),'ip_rules_no_resolve':sum(1 for ms in allms.values() for m in ms if m.kind=='ip_cidr' and 'no-resolve' in m.modifiers),'ip_rules_without_no_resolve':sum(1 for ms in allms.values() for m in ms if m.kind=='ip_cidr' and 'no-resolve' not in m.modifiers),'before_dedup_matchers':before_total,'after_dedup_matchers':after_total,'removed_matchers':removed,'removed_percent':round(removed/before_total*100,2) if before_total else 0.0,'dedup':stats,'groups_detail':group_details,'providers_detail':details,'upstreams':{n:{'type':s['type'],'url':s.get('url'),'path':s.get('path'),'sha256':details[n]['sha256'],'raw_rules':details[n]['raw_count']} for n,s in providers.items()},'asn_database':asn_audit,'semantic_audit':audit_payload,'acceptance':acceptance}
        report_json=json.dumps(report,ensure_ascii=False,indent=2)+'\n'; json.loads(report_json); (tmp/'report.json').write_text(report_json)
        md='# singbox-srs-converter Build Report\n\n## Summary\n\n| Item | Value |\n|---|---:|\n'+''.join(f'| {k} | {report[k]} |\n' for k in ('providers','groups','raw_rules','mapped_original_rules','unsupported_rules','asn_rules','asn_expanded_prefixes','before_dedup_matchers','after_dedup_matchers','removed_matchers','removed_percent'))
        (tmp/'report.md').write_text(md)
        (ROOT/'dist').exists() and shutil.rmtree(ROOT/'dist'); shutil.copytree(tmp,ROOT/'dist')
    finally: shutil.rmtree(tmp,ignore_errors=True)
if __name__=='__main__': main()
