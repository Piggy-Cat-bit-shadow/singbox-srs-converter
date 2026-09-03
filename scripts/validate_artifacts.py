#!/usr/bin/env python3
"""Validate generated artifacts using the same input semantics as build.py."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

from build import derive_groups


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_SEGMENT_TAGS = ("direct-pre", "ai", "direct-middle", "overseas", "ads", "direct-cn", "direct-cn-ip")
PRODUCTION_SEGMENT_PROVIDERS = {"ads": {"AntiAD"}}


def expected_provider_names(cfg):
    """Providers consumed by RULE-SET, preserving the builder's semantics."""
    return {name for group in derive_groups(cfg) for name in group["providers"]}


def fail(message):
    raise ValueError("ERROR: " + message)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON: {path}: {exc}")


def check(cfg, dist, sing_box="sing-box", required_tags=None, required_segment_providers=None):
    groups = derive_groups(cfg)
    expected_names = expected_provider_names(cfg)
    declared_names = set(cfg.get("rule-providers", {}))
    if expected_names != declared_names:
        missing = sorted(declared_names - expected_names)
        unknown = sorted(expected_names - declared_names)
        fail(f"provider usage mismatch: unused={missing}, undeclared={unknown}")
    expected_tags = [group["tag"] for group in groups]
    if required_tags is not None and tuple(expected_tags) != tuple(required_tags):
        fail(f"production segment contract mismatch: expected={list(required_tags)}, derived={expected_tags}")
    if required_segment_providers:
        groups_by_tag = {group["tag"]: set(group["providers"]) for group in groups}
        for tag, providers in required_segment_providers.items():
            missing = sorted(set(providers) - groups_by_tag.get(tag, set()))
            if missing:
                fail(f"production provider coverage missing from {tag}: {missing}")
    report = load_json(dist / "report.json")
    audit = load_json(dist / "semantic-audit.json")
    benchmark = load_json(dist / "memory-benchmark.json")
    if report.get("providers") != len(expected_names):
        fail(f"provider count mismatch: config={len(expected_names)} report={report.get('providers')}")
    if report.get("groups") != len(expected_tags):
        fail(f"group count mismatch: derived={len(expected_tags)} report={report.get('groups')}")
    source = {p.stem: p for p in (dist / "source").glob("*.json")}
    srs = {p.stem: p for p in (dist / "srs").glob("*.srs")}
    for label, files in (("source JSON", source), ("SRS", srs)):
        if len(files) != len(expected_tags):
            fail(f"expected {len(expected_tags)} {label} artifacts from report, found {len(files)}")
        for tag in expected_tags:
            if tag not in files:
                fail(f"missing {label} artifact: {tag}")
            if label == "SRS" and files[tag].stat().st_size == 0:
                fail(f"empty SRS artifact: {tag}")
    if set(source) != set(srs):
        fail(f"source/SRS tags do not match: source-only={sorted(set(source)-set(srs))}, srs-only={sorted(set(srs)-set(source))}")
    if report.get("unsupported_rules") != 0:
        fail(f"unsupported rules: {report.get('unsupported_rules')}")
    if audit.get("failed") != 0 or audit.get("passed") != audit.get("total"):
        fail(f"semantic audit failed: {audit.get('failed')}/{audit.get('total')}")
    if not benchmark.get("rss_comparable"):
        fail("memory benchmark RSS is not comparable")
    if benchmark["optimized"]["max_rss"] >= benchmark["legacy"]["max_rss"]:
        fail("optimized real-run RSS is not below legacy real-run RSS")
    acceptance = report.get("acceptance", {})
    if acceptance.get("source_binary_parity") is not True:
        fail("source/binary parity failed")
    if acceptance.get("route_coherence") is not True or audit.get("route_order") != expected_tags:
        fail("route order audit failed")
    coverage = acceptance.get("provider_coverage", {})
    if required_segment_providers:
        for tag, providers in required_segment_providers.items():
            for provider in providers:
                entry = coverage.get(provider, {})
                if entry.get("group") != tag or entry.get("coverage") not in {"emitted", "covered_by_same_segment"}:
                    fail(f"acceptance provider coverage missing for {provider} in {tag}")
    route = load_json(dist / "generated" / "sing-box-route.json").get("route", {})
    remote_sets = route.get("rule_set", [])
    remote_tags = [item.get("tag") for item in remote_sets]
    if remote_tags != expected_tags:
        fail(f"generated remote rule-set order mismatch: expected={expected_tags}, actual={remote_tags}")
    route_tags = [rule.get("rule_set", [None])[0] for rule in route.get("rules", []) if rule.get("rule_set")]
    if route_tags != expected_tags:
        fail(f"generated route rule order mismatch: expected={expected_tags}, actual={route_tags}")
    for item in remote_sets:
        url = item.get("url", "")
        path = urlparse(url).path
        if "/dist/srs/" in path:
            artifact = dist / "srs" / Path(path).name
            if artifact.suffix != ".srs" or not artifact.is_file() or artifact.stat().st_size == 0:
                fail(f"generated remote URL has no SRS artifact: {url}")
    for tag in expected_tags:
        result = subprocess.run([sing_box, "rule-set", "decompile", str(srs[tag]), "-o", "/dev/null"], capture_output=True, text=True)
        if result.returncode:
            fail(f"SRS compile/decompile failed: {tag}: {result.stderr.strip()}")
    print(f"PASS: {len(expected_names)} providers, {len(expected_tags)} segments, artifacts complete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("--dist", default=str(ROOT / "dist"))
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    try:
        cfg = yaml.safe_load(Path(args.input).read_text(encoding="utf-8"))
        check(cfg, Path(args.dist), args.sing_box, PRODUCTION_SEGMENT_TAGS, PRODUCTION_SEGMENT_PROVIDERS)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
