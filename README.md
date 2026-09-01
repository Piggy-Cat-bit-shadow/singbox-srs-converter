# singbox-srs-converter

Repository: `Piggy-Cat-bit-shadow/singbox-srs-converter`

将现有 Clash/Mihomo rule-provider 按原始 first-match 策略区间聚合，安全去重后生成 sing-box Rule Set Source Format v2，并使用官方 `sing-box rule-set compile` 编译为 SRS。项目只生成一套 merged-dedup 产物，不以 SagerNet 规则替换现有上游。

构建：

```bash
python3 scripts/build.py examples/my-rules.yaml
```

输出包含 7 个策略块：`direct-pre`、`ai`、`direct-middle`、`overseas`、`ads`、`direct-cn`、`direct-cn-ip`。去重仅发生在同一块内，且只删除完全重复、明确 suffix/domain 覆盖或父 CIDR 覆盖；不推断 keyword、regex、相邻 CIDR 或跨策略覆盖。无法严格表达的规则必须 fail closed。

`DOMAIN-WILDCARD` 使用 `*`→任意字符、`?`→单字符并加 `(?i)^...$`；普通 domain provider 的 `*` 只匹配一个 label。IP-ASN 应在构建时用 GeoLite2 ASN CSV 展开为 CIDR。Mihomo 的 `no-resolve` provenance 会保留在审计数据中，但 SRS 没有该字段；本项目不插入 `resolve` action，以免改变后续 domain first-match 语义。

三个本地 provider 位于 `local/`。`dist/` 为生成目录，GitHub Actions 每日使用最新稳定 sing-box 构建。
