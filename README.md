# singbox-srs-converter

Repository: `Piggy-Cat-bit-shadow/singbox-srs-converter`

## Only edit the input

Edit `examples/my-rules.yaml`. It is the sole source of truth for provider URLs, formats, policies, and first-match ordering. To add local rules, create a file in `local/` and reference it from `rule-providers` in that same input file.

Build everything:

```bash
python3 scripts/build.py examples/my-rules.yaml
```

## Output

Clients consume `dist/srs/*.srs`. Do not hand-edit `dist/`; it is rebuilt atomically.

- `dist/source/`: inspectable sing-box source JSON
- `dist/generated/sing-box-route.json`: route fragment derived from input order
- `dist/report.json`: build statistics and checksums
- `dist/semantic-audit.json`: required runtime regression results

The builder derives every contiguous `RULE-SET` policy segment from `rules:`. It preserves the current seven public tags while keeping non-adjacent policies separate. Compression is policy-segment-local: exact duplicates are removed, exact domains covered by suffixes are removed, child suffixes covered by a parent suffix are removed, and destination/source CIDRs are independently collapsed with `ipaddress.collapse_addresses`. Keywords and regexes are only exact-deduplicated.

For lower headless runtime object counts, destination fields (`domain`, suffix, keyword, regex, destination CIDR) are emitted as one OR rule per modifier bucket. Source CIDR, destination/source ports, network, and process fields are emitted as separate rules, so independent Mihomo rules are never accidentally converted into an AND condition. `dist/report.json` records matcher and headless-rule counts before and after aggregation for each segment.

`DOMAIN-WILDCARD` 使用 `*`→任意字符、`?`→单字符并加 `(?i)^...$`；普通 domain provider 的 `*` 只匹配一个 label。IP-ASN 应在构建时用 GeoLite2 ASN CSV 展开为 CIDR。Mihomo 的 `no-resolve` provenance 会保留在审计数据中，但 SRS 没有该字段；本项目不插入 `resolve` action，以免改变后续 domain first-match 语义。

Unsupported input fails closed. Three local providers live in `local/`; GitHub Actions rebuilds from the single input file.
