#!/usr/bin/env python3
"""
generate_ndjson_200.py
Generate a 200-line NDJSON test file for SAFE-T1306 detection testing.
No external dependencies. Deterministic output via fixed seed.
Usage:
  python3 generate_ndjson_200.py --out tests_200.jsonl
"""
import argparse
import json
import random
import uuid
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter

SEED = 42
TOTAL = 200

TRUSTED_ISSUERS = [
    "https://login.corp.example",
    "https://trusted-issuer.example"
]
ATTACK_ISSUERS = [
    "https://rogue-as.attacker.example",
    "https://unregistered.example",
    "https://nested.attacker.example",
    "https://service.attacker.example"
]
ALL_ISSUERS = TRUSTED_ISSUERS + ATTACK_ISSUERS

TRUSTED_KIDS = ["corp-kid-003", "corp-kid-004"]
UNKNOWN_KID_PREFIX = "attacker-kid-"

EXPECTED_AUDS = {"https://mcp.api.service"}

ACTIONS = [
    ("token.presented", 0.25),
    ("token.validated", 0.25),
    ("token.issued", 0.10),
    ("token.signature.valid", 0.10),
    ("token.used", 0.15),
    ("openid.configuration", 0.05),
    ("jwks.fetch", 0.05),
    ("discovery.fetch", 0.05)
]

SCOPES = ["read:all", "write:models", "read:all write:all", "admin", "*:*", "system.*"]

USER_AGENTS = ["curl/7.88.1", "python-requests/2.31.0", "Mozilla/5.0", "Go-http-client/1.1", "svc-client/1.2.3"]

SURGE_MINUTE = None  # will set to a minute bucket to create a surge
SURGE_THRESHOLD = 20  # for test, make surge threshold low so we can trigger

def choose_action():
    r = random.random()
    cum = 0.0
    for a, p in ACTIONS:
        cum += p
        if r <= cum:
            return a
    return ACTIONS[-1][0]

def iso(ts):
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def generate_base_records():
    random.seed(SEED)
    records = []
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    # pick a minute for surge
    global SURGE_MINUTE
    SURGE_MINUTE = now + timedelta(minutes=5)
    # prepare some jtis for replay
    replay_jtis = [f"replay-jti-{i}" for i in range(1,6)]
    # ensure some jtis will be reused across different IPs
    for i in range(TOTAL):
        action = choose_action()
        # timestamp spread across 10 minutes
        minute_offset = random.randint(0, 9)
        ts = now + timedelta(minutes=minute_offset)
        # force many discovery events into SURGE_MINUTE
        if random.random() < 0.08:
            ts = SURGE_MINUTE
            action = random.choice(["openid.configuration", "jwks.fetch", "discovery.fetch"])
        issuer = random.choice(ALL_ISSUERS)
        # choose kid
        if random.random() < 0.85:
            kid = random.choice(TRUSTED_KIDS)
        else:
            kid = UNKNOWN_KID_PREFIX + str(random.randint(1,50))
        # choose cnf.jkt states
        cnf_choice = random.random()
        if cnf_choice < 0.75:
            cnf = "thumb-" + uuid.uuid4().hex[:8]
        elif cnf_choice < 0.85:
            cnf = None
        elif cnf_choice < 0.92:
            cnf = ""
        else:
            cnf = "undefined"
        # scope
        scope = random.choice(SCOPES)
        # iat/exp
        iat = ts - timedelta(seconds=random.randint(0,300))
        # make some tokens with long lifetime
        if random.random() < 0.05:
            exp = iat + timedelta(hours=24)
        else:
            exp = iat + timedelta(minutes=random.randint(5,120))
        # jti
        if action == "token.used":
            # sometimes reuse a replay jti
            if random.random() < 0.3:
                jti = random.choice(replay_jtis)
            else:
                jti = "jti-" + uuid.uuid4().hex[:8]
        else:
            jti = None
        # source ip
        src_ip = f"198.51.{random.randint(0,255)}.{random.randint(1,254)}" if random.random() < 0.8 else f"203.0.{random.randint(0,255)}.{random.randint(1,254)}"
        rec = {
            "case": f"case_{i+1:03d}",
            "timestamp": iso(ts),
            "event.action": action,
            "source.ip": src_ip,
            "user.id": random.choice(["alice","bob","svc-bot","ops","charlie","eve","dave"]),
            "user_agent": random.choice(USER_AGENTS),
            "http.request.uri": random.choice(["/api/v1/models/query","/v1/context","/v1/admin"]),
            # include both nested and flattened shapes randomly
            "jwt": None,
            "jwt.iss": None,
            "jwt.aud": None,
            "jwt.kid": None,
            "jwt.cnf.jkt": None,
            "jwt.scope": None,
            "jwt.exp": int(exp.timestamp()),
            "jwt.iat": int(iat.timestamp()),
            "jwt.jti": jti,
            "issuer.url": issuer if action in ("openid.configuration","discovery.fetch","jwks.fetch") else None,
            "jwks_uri": (issuer + "/.well-known/jwks.json") if action in ("openid.configuration","jwks.fetch") else None,
            "client_id": "client-" + str(random.randint(1,20))
        }
        # populate jwt fields either nested or flattened
        if random.random() < 0.5:
            rec["jwt"] = {
                "iss": issuer,
                "aud": "https://mcp.api.service",
                "kid": kid,
                "cnf": {"jkt": cnf} if cnf is not None else {"jkt": None},
                "scope": scope,
                "exp": rec["jwt.exp"],
                "iat": rec["jwt.iat"],
            }
            if jti:
                rec["jwt"]["jti"] = jti
        else:
            rec["jwt.iss"] = issuer
            rec["jwt.aud"] = "https://mcp.api.service"
            rec["jwt.kid"] = kid
            rec["jwt.cnf.jkt"] = cnf
            rec["jwt.scope"] = scope
            if jti:
                rec["jwt.jti"] = jti
        records.append(rec)
    return records

# detection heuristics used to compute expected
def issuer_matches(iss):
    if not iss:
        return False
    s = iss.lower()
    return ("attacker" in s) or ("unregistered" in s)

def is_missing_pop(cnf):
    if cnf is None:
        return True
    if isinstance(cnf, str) and cnf.strip() == "":
        return True
    if isinstance(cnf, str) and cnf.strip().lower() == "undefined":
        return True
    return False

def scope_is_super(scope):
    if not scope:
        return False
    s = scope.lower()
    return ("admin" in s) or ("*:*" in s) or s.startswith("system.")

def compute_expected(records):
    # precompute per-minute discovery counts and jti->src_ips
    per_minute = Counter()
    jti_srcips = defaultdict(set)
    for rec in records:
        action = rec.get("event.action")
        ts = rec.get("timestamp")
        minute = ts[:16]  # YYYY-MM-DDTHH:MM
        if action in ("openid.configuration","jwks.fetch","discovery.fetch"):
            per_minute[minute] += 1
        # collect jti src ips
        jti = None
        if rec.get("jwt") and isinstance(rec["jwt"], dict):
            jti = rec["jwt"].get("jti")
        else:
            jti = rec.get("jwt.jti")
        if jti and rec.get("source.ip"):
            jti_srcips[jti].add(rec.get("source.ip"))
    # now compute expected per record
    expected_list = []
    for rec in records:
        action = rec.get("event.action")
        # extract issuer and cnf
        if rec.get("jwt") and isinstance(rec["jwt"], dict):
            issuer = rec["jwt"].get("iss")
            cnf = rec["jwt"].get("cnf", {}).get("jkt")
            kid = rec["jwt"].get("kid")
            scope = rec["jwt"].get("scope")
            aud = rec["jwt"].get("aud")
            jti = rec["jwt"].get("jti")
            exp = rec["jwt"].get("exp")
            iat = rec["jwt"].get("iat")
        else:
            issuer = rec.get("jwt.iss")
            cnf = rec.get("jwt.cnf.jkt")
            kid = rec.get("jwt.kid")
            scope = rec.get("jwt.scope")
            aud = rec.get("jwt.aud")
            jti = rec.get("jwt.jti")
            exp = rec.get("jwt.exp")
            iat = rec.get("jwt.iat")
        ts = rec.get("timestamp")
        minute = ts[:16]
        detected = False
        reasons = []
        # legacy suspicious issuer + missing PoP
        if issuer_matches(issuer) and is_missing_pop(cnf) and action in ("token.presented","token.validated","token.used","token.signature.valid"):
            detected = True
            reasons.append("suspicious_issuer_missing_pop")
        # token.signature.valid unknown kid
        if action == "token.signature.valid" and kid and kid not in TRUSTED_KIDS:
            detected = True
            reasons.append("unknown_kid")
        # token.validated missing PoP when PoP required
        if action == "token.validated" and is_missing_pop(cnf):
            detected = True
            reasons.append("missing_pop_on_validated")
        # token.issued with super scope
        if action == "token.issued" and scope_is_super(scope):
            detected = True
            reasons.append("super_scope_issued")
        # unusual lifetime
        if action == "token.issued" and exp and iat and (exp - iat) > 3600:
            detected = True
            reasons.append("unusual_lifetime")
        # abnormal aud + admin
        if action == "token.validated" and aud and aud not in EXPECTED_AUDS and scope_is_super(scope):
            detected = True
            reasons.append("abnormal_aud_admin_scope")
        # token replay without PoP
        if action == "token.used" and jti:
            distinct = len(jti_srcips.get(jti, set()))
            if distinct >= 2 and is_missing_pop(cnf):
                detected = True
                reasons.append("replay_without_pop")
        # discovery surge
        if action in ("openid.configuration","jwks.fetch","discovery.fetch"):
            if per_minute.get(minute,0) > SURGE_THRESHOLD:
                detected = True
                reasons.append("discovery_surge")
        expected_list.append((detected, reasons))
    return expected_list

def open_output(filename):
    if filename in (None, "-", "stdout"):
        return sys.stdout
    return open(filename, "w", encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="Generate 200-line NDJSON test file")
    parser.add_argument("--out", required=False, help="Output NDJSON file path")
    args = parser.parse_args()
    records = generate_base_records()
    expected_info = compute_expected(records)
    # attach expected and write NDJSON
    with open_output(args.out) as fh:
        for rec, (detected, reasons) in zip(records, expected_info):
            rec_out = {k:v for k,v in rec.items() if v is not None}
            rec_out["expected"] = bool(detected)
            if reasons:
                rec_out["expected_reasons"] = reasons
            fh.write(json.dumps(rec_out, ensure_ascii=False) + "\n")
    # summary
    total = len(records)
    positives = sum(1 for d,r in expected_info if d)
    print(f"Generated {total} records -> {positives} expected alerts written to {args.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
