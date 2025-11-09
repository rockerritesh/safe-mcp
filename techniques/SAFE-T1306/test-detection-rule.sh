#!/usr/bin/env python3
"""
safe_t1306_with_yaml.py
Load detection rules from a YAML file and apply them to an NDJSON log file.
Outputs alerts as NDJSON lines.

Requires: pyyaml (pip install pyyaml)
"""
import argparse
import json
import sys
import fnmatch
from datetime import datetime, timezone
from collections import defaultdict, Counter

try:
    import yaml
except Exception:
    print("[ERROR] PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Default fallbacks
DEFAULT_SURGE_THRESHOLD = 50
DEFAULT_REPLAY_THRESHOLD = 2
DEFAULT_LIFETIME_THRESHOLD = 3600

def parse_args():
    p = argparse.ArgumentParser(description="SAFE-T1306 harness loading rules from YAML")
    p.add_argument("--logfile", default="-", help="NDJSON log file")
    p.add_argument("--rules-file", default="./detection-rule.yml", help="YAML detection-rule file (multi-doc supported)")
    p.add_argument("--trusted-issuers", default="", help="Comma-separated trusted issuer URLs")
    p.add_argument("--trusted-kids", default="", help="Comma-separated trusted kid values")
    p.add_argument("--expected-audiences", default="", help="Comma-separated expected aud values")
    p.add_argument("--pop-required", default="true", help="Whether PoP is required (true/false)")
    p.add_argument("--alert-output", default="", help="Write alerts NDJSON to this file (optional)")
    return p.parse_args()

def open_input(path):
    if path in ("", "-", "stdin"):
      return sys.stdin 
    return open(path, "r", encoding="utf-8")

def load_ndjson(path):
    recs = []
    with open_input(path) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[WARN] skipping invalid JSON line {i}", file=sys.stderr)
    return recs

def load_rules_yaml(path):
    docs = []
    with open(path, "r", encoding="utf-8") as fh:
        try:
            for d in yaml.safe_load_all(fh):
                if d:
                    docs.append(d)
        except yaml.YAMLError as e:
            print(f"[ERROR] failed to parse YAML rules: {e}", file=sys.stderr)
            sys.exit(2)
    return docs

def get_nested(rec, *keys):
    cur = rec
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur

def extract_jwt_field(rec, key):
    jwt = rec.get("jwt")
    if isinstance(jwt, dict):
        if "." in key:
            parts = key.split(".")
            v = get_nested(jwt, *parts)
            if v is not None:
                return v
        else:
            if key in jwt and jwt[key] is not None:
                return jwt[key]
    flat = f"jwt.{key}"
    if flat in rec and rec[flat] is not None:
        return rec[flat]
    if key in rec and rec[key] is not None:
        return rec[key]
    return None

def extract_field(rec, names):
    for n in names:
        if "." in n:
            parts = n.split(".")
            v = get_nested(rec, *parts)
            if v is not None:
                return v
        else:
            if n in rec and rec[n] is not None:
                return rec[n]
    return None

def parse_threshold_expr(expr, default=None):
    if expr is None:
        return default
    if isinstance(expr, (int, float)):
        return int(expr)
    s = str(expr).strip()
    if s.startswith(">"):
        try:
            return int(s[1:])
        except Exception:
            return default
    try:
        return int(s)
    except Exception:
        return default

def pattern_list_from_value(val):
    # val may be list of strings or list containing dicts like {'not_in': 'trusted_issuer_list'}
    if not isinstance(val, list):
        return []
    patterns = []
    for v in val:
        if isinstance(v, str):
            patterns.append(v)
        elif isinstance(v, dict):
            # skip dict entries here; handled separately
            continue
    return patterns

def contains_not_in(val):
    # return the not_in token if present, else None
    if not isinstance(val, list):
        return None
    for v in val:
        if isinstance(v, dict) and "not_in" in v:
            return v["not_in"]
    return None

def issuer_matches_patterns(iss, patterns):
    if not iss:
        return False
    iss_l = iss.lower()
    for pat in patterns:
        if fnmatch.fnmatch(iss_l, pat.lower()):
            return True
    return False

def scope_contains(scope, patterns):
    if not scope:
        return False
    s = scope if isinstance(scope, str) else " ".join(scope)
    s_l = s.lower()
    for p in patterns:
        p_l = p.lower()
        if p_l.endswith("."):
            if p_l in s_l:
                return True
        elif "*" in p_l:
            # simple wildcard match
            if fnmatch.fnmatch(s_l, p_l):
                return True
            if fnmatch.fnmatch(s_l, f"*{p_l.strip('*')}*"):
                return True
        else:
            if p_l in s_l:
                return True
    return False

def is_missing_pop(cnf_jkt, missing_values):
    if cnf_jkt is None:
        return True if None in missing_values else False
    if isinstance(cnf_jkt, str):
        if cnf_jkt.strip() == "" and "" in missing_values:
            return True
        if cnf_jkt.strip().lower() == "undefined" and "undefined" in missing_values:
            return True
    return False

def build_config_from_rules(docs):
    cfg = {
        "iss_patterns": [],
        "missing_cnf_values": {None, "", "undefined"},
        "super_scope_patterns": [],
        "lifetime_threshold": DEFAULT_LIFETIME_THRESHOLD,
        "surge_threshold": DEFAULT_SURGE_THRESHOLD,
        "replay_threshold": DEFAULT_REPLAY_THRESHOLD,
        "check_unknown_kid": False,
        "check_untrusted_issuer": False
    }
    for d in docs:
        det = d.get("detection") or {}
        sel = det.get("selection") or {}
        # jwt.iss patterns
        if "jwt.iss" in sel:
            cfg["iss_patterns"].extend(pattern_list_from_value(sel["jwt.iss"]))
            # check for not_in token
            if contains_not_in(sel["jwt.iss"]):
                cfg["check_untrusted_issuer"] = True
        # jwt.cnf.jkt missing values
        if "jwt.cnf.jkt" in sel:
            vals = sel["jwt.cnf.jkt"]
            if isinstance(vals, list):
                # normalize None, '', 'undefined'
                mv = set()
                for v in vals:
                    if v is None:
                        mv.add(None)
                    elif isinstance(v, str):
                        mv.add(v)
                cfg["missing_cnf_values"] = mv
        # token.scope|contains or jwt.scope|contains
        for k in sel.keys():
            if "|contains" in k and ("scope" in k):
                cfg["super_scope_patterns"].extend(pattern_list_from_value(sel[k]))
        # token.exp - token.iat threshold
        if "token.exp - token.iat" in sel:
            cfg["lifetime_threshold"] = parse_threshold_expr(sel["token.exp - token.iat"], cfg["lifetime_threshold"])
        # count_per_minute threshold
        if "count_per_minute" in sel:
            cfg["surge_threshold"] = parse_threshold_expr(sel["count_per_minute"], cfg["surge_threshold"])
        # token.jti replay threshold
        for k in sel.keys():
            if "|count_distinct_src_ip" in k and "jti" in k:
                cfg["replay_threshold"] = parse_threshold_expr(sel[k], cfg["replay_threshold"])
        # token.kid not_in
        if "token.kid" in sel:
            if contains_not_in(sel["token.kid"]):
                cfg["check_unknown_kid"] = True
    return cfg

def emit_alert(out_fh, alert):
    line = json.dumps(alert, ensure_ascii=False)
    print(line)
    if out_fh:
        out_fh.write(line + "\n")
        out_fh.flush()

def parse_time_iso(ts):
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts)
    s = str(ts).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return None

def main():
    args = parse_args()
    trusted_issuers = {s.strip() for s in args.trusted_issuers.split(",") if s.strip()}
    trusted_kids = {s.strip() for s in args.trusted_kids.split(",") if s.strip()}
    expected_auds = {s.strip() for s in args.expected_audiences.split(",") if s.strip()}
    pop_required = str(args.pop_required).lower() in ("1", "true", "yes")

    records = load_ndjson(args.logfile)
    if not records:
        print("[ERROR] no records loaded", file=sys.stderr)
        sys.exit(2)

    docs = load_rules_yaml(args.rules_file)
    cfg = build_config_from_rules(docs)

    alerts_fh = open(args.alert_output, "w", encoding="utf-8") if args.alert_output else None

    # state
    jti_srcips = defaultdict(set)
    per_minute_counts = Counter()
    total_alerts = 0

    for rec in records:
        action = rec.get("event.action") or rec.get("event") or rec.get("action") or ""
        action = str(action)
        issuer_url = extract_field(rec, ["issuer.url", "issuer", "jwt.iss", "iss"])
        token_kid = extract_jwt_field(rec, "kid")
        token_cnf_jkt = extract_jwt_field(rec, "cnf.jkt")
        token_scope = extract_jwt_field(rec, "scope") or extract_jwt_field(rec, "jwt.scope")
        token_aud = extract_jwt_field(rec, "aud") or extract_field(rec, ["aud"])
        token_exp = parse_time_iso(extract_jwt_field(rec, "exp") or rec.get("token.exp") or rec.get("exp"))
        token_iat = parse_time_iso(extract_jwt_field(rec, "iat") or rec.get("token.iat") or rec.get("iat"))
        token_jti = extract_jwt_field(rec, "jti") or rec.get("token.jti")
        src_ip = rec.get("source.ip") or rec.get("src_ip") or rec.get("client.ip") or rec.get("source_ip")
        ts = rec.get("timestamp")
        minute_bucket = None
        try:
            if ts:
                t = ts
                if isinstance(t, str) and t.endswith("Z"):
                    t = t[:-1] + "+00:00"
                dt = datetime.fromisoformat(t) if isinstance(t, str) else None
                if dt:
                    minute_bucket = int(dt.replace(tzinfo=timezone.utc).timestamp() // 60)
        except Exception:
            minute_bucket = None

        # surge detection for discovery actions
        if action in ("openid.configuration", "jwks.fetch", "discovery.fetch"):
            key = (minute_bucket, action)
            per_minute_counts[key] += 1
            if per_minute_counts[key] > cfg["surge_threshold"]:
                alert = {
                    "rule_id": "0f21a145-9441-4db2-9b70-22d91f85b1a9",
                    "title": "Sudden Surge in Discovery or JWKS Requests",
                    "severity": "medium",
                    "reason": "surge_in_discovery_or_jwks_requests",
                    "minute_bucket": minute_bucket,
                    "action": action,
                    "count": per_minute_counts[key],
                    "issuer.url": issuer_url
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

        # Suspicious issuer or discovery endpoint change
        if action in ("discovery.fetch", "openid.configuration", "jwks.fetch"):
            if issuer_url:
                if cfg["check_untrusted_issuer"]:
                    if issuer_url not in trusted_issuers and not issuer_matches_patterns(issuer_url, cfg["iss_patterns"]):
                        alert = {
                            "rule_id": "930b6b7d-1de4-49b8-b857-1b2eac1b2383",
                            "title": "Suspicious OAuth Issuer or Discovery Endpoint Change",
                            "severity": "high",
                            "reason": "new_or_untrusted_issuer_discovery",
                            "issuer.url": issuer_url,
                            "jwks_uri": rec.get("jwks_uri") or rec.get("jwks.uri")
                        }
                        emit_alert(alerts_fh, alert)
                        total_alerts += 1

        # New JWKS Key ID Detected
        if action == "token.signature.valid" and cfg["check_unknown_kid"]:
            if token_kid and token_kid not in trusted_kids:
                alert = {
                    "rule_id": "62f91ac7-4d5d-4a56-9b2f-0a94e7fbe89f",
                    "title": "New JWKS Key ID Detected",
                    "severity": "high",
                    "reason": "unknown_kid",
                    "kid": token_kid,
                    "iss": issuer_url,
                    "aud": token_aud
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

        # Token Missing PoP
        if action == "token.validated" and pop_required:
            if is_missing_pop(token_cnf_jkt, cfg["missing_cnf_values"]):
                alert = {
                    "rule_id": "55b3c14e-2f1e-4d8e-87a8-4b8d1b73e332",
                    "title": "Token Missing Proof of Possession (PoP)",
                    "severity": "high",
                    "reason": "missing_pop_binding",
                    "iss": issuer_url,
                    "aud": token_aud,
                    "kid": token_kid
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

        # Super-token scope and unusual lifetime
        if action == "token.issued":
            if scope_contains(token_scope, cfg["super_scope_patterns"]):
                alert = {
                    "rule_id": "4a94c222-bb76-4f8a-9874-43182c449b4c",
                    "title": "Super-Token Issued With Overly Broad Scope",
                    "severity": "high",
                    "reason": "overly_broad_scope",
                    "scope": token_scope,
                    "client_id": rec.get("client_id"),
                    "iss": issuer_url
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1
            if token_exp is not None and token_iat is not None:
                if (token_exp - token_iat) > cfg["lifetime_threshold"]:
                    alert = {
                        "rule_id": "7c8d88a5-9bfa-4f61-bf2d-d46874a598df",
                        "title": "Unusual Token Lifetime or Expiry",
                        "severity": "medium",
                        "reason": "unusual_token_lifetime",
                        "exp": token_exp,
                        "iat": token_iat,
                        "iss": issuer_url
                    }
                    emit_alert(alerts_fh, alert)
                    total_alerts += 1

        # Abnormal audience + admin scope
        if action == "token.validated":
            if expected_auds and token_aud and token_aud not in expected_auds and scope_contains(token_scope, ["admin"]):
                alert = {
                    "rule_id": "b2eae722-662d-4dc9-9df1-824aaf6a8b24",
                    "title": "Abnormal Audience or Scope Combination",
                    "severity": "medium",
                    "reason": "abnormal_aud_scope_combo",
                    "aud": token_aud,
                    "scope": token_scope,
                    "iss": issuer_url
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

        # Token replay without PoP
        if action == "token.used" and token_jti:
            if src_ip:
                jti_srcips[token_jti].add(src_ip)
            distinct = len(jti_srcips[token_jti])
            if distinct >= cfg["replay_threshold"] and is_missing_pop(token_cnf_jkt, cfg["missing_cnf_values"]):
                alert = {
                    "rule_id": "1e1e8a13-dc2d-41c1-8ec2-2ce0f51c8240",
                    "title": "Token Replay Without PoP Binding",
                    "severity": "critical",
                    "reason": "token_replay_without_pop",
                    "jti": token_jti,
                    "distinct_src_ip_count": distinct,
                    "src_ips": list(jti_srcips[token_jti]),
                    "iss": issuer_url
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

        # Legacy consolidated suspicious issuer + missing PoP
        if action in ("token.presented", "token.validated", "token.used", "token.signature.valid"):
            if issuer_matches_patterns(issuer_url, cfg["iss_patterns"]) and is_missing_pop(token_cnf_jkt, cfg["missing_cnf_values"]):
                alert = {
                    "rule_id": "15d7a84f-98a6-4f3a-89a3-abea0e37a9d1",
                    "title": "Suspicious OAuth Issuer or Missing PoP in MCP Token",
                    "severity": "high",
                    "reason": "suspicious_issuer_and_missing_pop",
                    "iss": issuer_url,
                    "kid": token_kid,
                    "scope": token_scope
                }
                emit_alert(alerts_fh, alert)
                total_alerts += 1

    if alerts_fh:
        alerts_fh.close()

    print(f"[INFO] processed {len(records)} records, emitted {total_alerts} alerts", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    main()
