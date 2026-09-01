#!/usr/bin/env python3
import argparse, csv, gzip, hashlib, ipaddress, io, json, re, shutil, subprocess, tempfile, urllib.request, ssl, time, yaml
import certifi
from dataclasses import dataclass
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
GROUPS=yaml.safe_load((ROOT/'config/groups.yaml').read_text())['groups']
SAMPLES={k:[] for k in ('exact_duplicates_removed','domain_covered_by_suffix','suffix_covered_by_parent_suffix','ipcidr_duplicates_removed','ipcidr_covered_by_parent')}
@dataclass(frozen=True)
class M:
    kind:str; value:str; modifiers:tuple=(); provider:str=''; source:str=''; expanded_from:str|None=None

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
def load(pname,spec,base):
    if spec['type']=='file': data=(ROOT/spec['path']).read_bytes()
    else:
        req=urllib.request.Request(spec['url'],headers={'User-Agent':'singbox-srs-converter'}); ctx=ssl.create_default_context(cafile=certifi.where())
        last=None
        for attempt in range(5):
            try: data=urllib.request.urlopen(req,timeout=60,context=ctx).read(); break
            except Exception as e:
                last=e
                if attempt==4: raise RuntimeError(f'{pname}: download failed: {e}') from e
                time.sleep(2*(attempt+1))
    sha=hashlib.sha256(data).hexdigest(); fmt=spec.get('format','yaml'); text=data.decode('utf-8-sig')
    if fmt=='text': vals=[x for x in text.splitlines() if x.strip() and not x.startswith('#')]
    else:
        obj=yaml.safe_load(text); vals=obj if isinstance(obj,list) else obj.get('payload',obj.get('rules')) if isinstance(obj,dict) else None
        if not isinstance(vals,list): raise ValueError('invalid YAML provider structure')
    ms=[]
    for raw in vals: ms += parse(str(raw),spec['behavior'],pname)
    return ms,sha,len(vals)
def dedup(ms):
    stats={k:0 for k in SAMPLES}; seen=set(); unique=[]
    for m in ms:
        key=(m.kind,m.value,m.modifiers)
        if key in seen: stats['exact_duplicates_removed']+=1
        else: seen.add(key); unique.append(m)
    suffixes={m.value for m in unique if m.kind=='domain_suffix'}
    redundant={s for s in suffixes if any('.'.join(s.split('.')[i:]) in suffixes for i in range(1,len(s.split('.'))))}
    stats['suffix_covered_by_parent_suffix']=sum(1 for m in unique if m.kind=='domain_suffix' and m.value in redundant)
    valid_suffixes=suffixes-redundant
    def covered(d):
        parts=d.split('.')
        return any('.'.join(parts[i:]) in valid_suffixes for i in range(len(parts)))
    nets={m.value for m in unique if m.kind=='ip_cidr'}
    def netcovered(v):
        n=ipaddress.ip_network(v); cur=n
        while cur.prefixlen:
            cur=cur.supernet()
            if str(cur) in nets: return True
        return False
    out=[]
    for m in unique:
        if m.kind=='domain_suffix' and m.value in redundant: continue
        if m.kind=='domain' and covered(m.value): stats['domain_covered_by_suffix']+=1; continue
        if m.kind=='ip_cidr' and netcovered(m.value): stats['ipcidr_covered_by_parent']+=1; continue
        out.append(m)
    return out,stats
def expand_asn(allms):
    need={m.value for ms in allms.values() for m in ms if m.kind in ('asn','src_asn')}
    if not need: return allms, {}
    ctx=ssl.create_default_context(cafile=certifi.where()); meta=json.loads(urllib.request.urlopen('https://api.github.com/repos/FyraLabs/geolite2/releases/latest',context=ctx).read())
    assets={x['name']:x['browser_download_url'] for x in meta['assets']}; result={k:[] for k in need}; audit={'release':meta['tag_name'],'prefixes':{}}
    for name,url in assets.items():
        if not name.endswith('.csv') or 'GeoLite2-ASN-Blocks-' not in name: continue
        raw=urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'singbox-srs-converter'}),context=ctx).read(); count=0
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
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('input'); ap.add_argument('--base-url',default='https://raw.githubusercontent.com/Piggy-Cat-bit-shadow/singbox-srs-converter/main'); ap.add_argument('--sing-box',default='sing-box'); a=ap.parse_args()
    cfg=yaml.safe_load(Path(a.input).read_text()); providers=cfg['rule-providers']; names=[p for g in GROUPS for p in g['providers']]
    if len(providers)!=53 or len(names)!=53 or set(names)!=set(providers): raise SystemExit('provider/group mismatch; expected exactly 53 providers')
    tmp=Path(tempfile.mkdtemp(prefix='srs-build-',dir=ROOT)); (tmp/'source').mkdir(); (tmp/'srs').mkdir(); (tmp/'generated').mkdir(); details={}; allms={}; stats={k:0 for k in SAMPLES}
    try:
        for n,s in providers.items():
            ms,sha,raw=load(n,s,ROOT); allms[n]=ms; details[n]={'raw_count':raw,'parsed_count':len(ms),'sha256':sha,'source':s.get('url',s.get('path'))}
        asn_rules=sum(1 for ms in allms.values() for m in ms if m.kind in ('asn','src_asn'))
        allms,asn_audit=expand_asn(allms)
        group_details={}; before_total=after_total=0
        for g in GROUPS:
            ms=[m for n in g['providers'] for m in allms[n]]; before=len(ms); clean,st=dedup(ms)
            before_total += before; after_total += len(clean)
            for k,v in st.items(): stats[k]+=v
            fields={}; independent=[]
            for m in clean:
                if m.kind=='asn' or m.kind=='src_asn': raise ValueError(f'ASN requires GeoLite2 expansion: {m.source}')
                if m.kind in ('process_name',): independent += [{'process_name':[m.value]},{'package_name':[m.value]}]
                elif m.kind in ('port','port_range','source_port','source_port_range'): fields.setdefault(m.kind,[]).extend(json.loads(m.value))
                elif m.kind in ('source_ip_cidr','network','process_path','process_path_regex'): independent.append({m.kind:[m.value]})
                else: fields.setdefault(m.kind,[]).append(m.value)
            if fields: independent.insert(0,{k:list(dict.fromkeys(v)) for k,v in fields.items() if v})
            rules=independent
            if not rules: raise ValueError(f'empty group {g["tag"]}')
            (tmp/'source'/f'{g["tag"]}.json').write_text(json.dumps({'version':2,'rules':rules},ensure_ascii=False,separators=(',',':')),encoding='utf-8')
            subprocess.run([a.sing_box,'rule-set','compile','--output',str(tmp/'srs'/f'{g["tag"]}.srs'),str(tmp/'source'/f'{g["tag"]}.json')],check=True)
            group_details[g['tag']]={'provider_count':len(g['providers']),'raw_rules':sum(details[n]['raw_count'] for n in g['providers']),'before_dedup':before,'after_dedup':len(clean),'removed':before-len(clean),'srs_bytes':(tmp/'srs'/f'{g["tag"]}.srs').stat().st_size}
        route={'route':{'rule_set':[{'type':'remote','tag':g['tag'],'format':'binary','url':a.base_url.rstrip('/')+'/dist/srs/'+g['tag']+'.srs','update_interval':'1d'} for g in GROUPS],'rules':[{'ip_cidr':['0.0.0.0/32'],'action':'reject','method':'default'}]+[({'rule_set':[g['tag']],'action':'reject','method':'drop'} if g['policy']=='REJECT-DROP' else {'rule_set':[g['tag']],'action':'route','outbound':{'DIRECT':'direct','🤖 AI':'ai','⚡ 海外高速':'overseas'}[g['policy']]}) for g in GROUPS],'final':'overseas'}}
        (tmp/'generated'/'sing-box-route.json').write_text(json.dumps(route,ensure_ascii=False,indent=2)+'\n')
        removed=before_total-after_total
        if removed != sum(stats.values()): raise ValueError('dedup accounting mismatch')
        report={'version':1,'providers':len(providers),'groups':len(GROUPS),'raw_rules':sum(x['raw_count'] for x in details.values()),'mapped_original_rules':sum(x['parsed_count'] for x in details.values()),'unsupported_rules':0,'asn_rules':asn_rules,'asn_expanded_prefixes':sum(v for v in asn_audit.get('prefixes',{}).values()),'ip_rules_no_resolve':sum(1 for ms in allms.values() for m in ms if m.kind=='ip_cidr' and 'no-resolve' in m.modifiers),'ip_rules_without_no_resolve':sum(1 for ms in allms.values() for m in ms if m.kind=='ip_cidr' and 'no-resolve' not in m.modifiers),'before_dedup_matchers':before_total,'after_dedup_matchers':after_total,'removed_matchers':removed,'removed_percent':round(removed/before_total*100,2) if before_total else 0.0,'dedup':stats,'groups_detail':group_details,'providers_detail':details,'upstreams':{n:{'type':s['type'],'url':s.get('url'),'path':s.get('path'),'sha256':details[n]['sha256'],'raw_rules':details[n]['raw_count']} for n,s in providers.items()},'asn_database':asn_audit}
        report_json=json.dumps(report,ensure_ascii=False,indent=2)+'\n'; json.loads(report_json); (tmp/'report.json').write_text(report_json)
        md='# singbox-srs-converter Build Report\n\n## Summary\n\n| Item | Value |\n|---|---:|\n'+''.join(f'| {k} | {report[k]} |\n' for k in ('providers','groups','raw_rules','mapped_original_rules','unsupported_rules','asn_rules','asn_expanded_prefixes','before_dedup_matchers','after_dedup_matchers','removed_matchers','removed_percent'))
        (tmp/'report.md').write_text(md)
        (ROOT/'dist').exists() and shutil.rmtree(ROOT/'dist'); shutil.copytree(tmp,ROOT/'dist')
    finally: shutil.rmtree(tmp,ignore_errors=True)
if __name__=='__main__': main()
