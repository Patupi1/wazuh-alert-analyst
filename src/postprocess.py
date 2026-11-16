"""Deterministic post-processing of the analyst's answer (stdlib only; copied to sonetto next to
analyze_today.py).

escalate(batch, answer)  A successful SSH login (rule 5715) from an address that is also brute-forcing
                         (5710 / 5712) is critical whatever the model says, and some needs_a_look item
                         must name that login. Every v2 run missed this case.
evidence_check(batch, answer)
                         Every IP, path and host the answer mentions must appear in the batch. Unknown
                         values are removed from evidence lists and reported; free-text fields are
                         left as written but the unknown values are listed so the report can flag them.
"""
import json
import re

BRUTE_RULES = {"5710", "5712"}
LOGIN_RULE = "5715"
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(r"(?<![\w/])/(?:etc|usr|var|home|root|tmp|dev|opt|srv|bin)/[\w./-]+")


def brute_force_logins(batch):
    """(login entry, ip) for each 5715 whose src_ip also appears on a 5710/5712 entry."""
    alerts = batch.get("alerts", [])
    brute = {a.get("src_ip") for a in alerts if str(a.get("rule")) in BRUTE_RULES and a.get("src_ip")}
    return [(a, a["src_ip"]) for a in alerts if str(a.get("rule")) == LOGIN_RULE and a.get("src_ip") in brute]


def names_login(item, user):
    what = str(item.get("what", "")).lower()
    said = ("success" in what or "logged in" in what or "login as" in what) and "no success" not in what
    return said and (not user or user.lower() in what or user in (item.get("evidence") or []))


def escalate(batch, answer):
    """Return (answer, notes). `answer` is the parsed dict (modified in place); notes lists what changed."""
    notes = []
    hits = brute_force_logins(batch)
    if not hits or not isinstance(answer, dict):
        return answer, notes
    if answer.get("severity") != "critical":
        notes.append(f"severity {answer.get('severity')!r} -> 'critical' (brute force followed by a login from the same address)")
        answer["severity"] = "critical"
    looks = answer.get("needs_a_look")
    if not isinstance(looks, list):
        looks = answer["needs_a_look"] = []
    for entry, ip in hits:
        host, user = entry.get("agent"), entry.get("user")
        want = [v for v in (ip, host, user) if v]
        what = f"SSH brute force from {ip} against {host} followed by a successful login as {user} from the same address"
        same_ip = [l for l in looks if isinstance(l, dict) and
                   (ip in (l.get("evidence") or []) or ip in str(l.get("what", "")))]
        if any(names_login(l, user) for l in same_ip):
            continue
        if same_ip:  # the model saw the brute force but not the login: rewrite that item
            l = same_ip[0]
            l["what"] = what
            l["evidence"] = sorted(set(l.get("evidence") or []) | set(want))
            l["likely_innocent"] = None
            notes.append(f"rewrote the item on {ip} to name the login as {user}")
        else:
            item = {"what": what, "evidence": sorted(set(want)), "likely_innocent": None,
                    "check": f"treat {host} as compromised until checked: review {user}'s shell history and "
                             f"authorized_keys, and block {ip}"}
            pos = 1 if answer.get("prompt_injection") is True and looks else 0
            looks.insert(pos, item)
            notes.append(f"added an item for the login as {user} from {ip}")
    return answer, notes


def entities(text, hosts):
    ents = set(IP_RE.findall(text)) | {p.rstrip(".,") for p in PATH_RE.findall(text)}
    low = text.lower()
    ents |= {h for h in hosts if re.search(rf"(?<![\w-]){re.escape(h.lower())}(?![\w-])", low)}
    return ents


def evidence_check(batch, answer, hosts=()):
    """Return (answer, unknown). Removes evidence values not found in the batch; `unknown` lists every
    IP / path / host mentioned anywhere in the answer that the batch does not contain."""
    src = json.dumps(batch, ensure_ascii=False)
    hosts = set(hosts) | set(batch.get("agents", {})) | {a.get("agent") for a in batch.get("alerts", []) if a.get("agent")}
    text = json.dumps(answer, ensure_ascii=False) if not isinstance(answer, str) else answer
    unknown = sorted(e for e in entities(text, hosts) if e not in src)
    if isinstance(answer, dict):
        for l in answer.get("needs_a_look") or []:
            if isinstance(l, dict) and isinstance(l.get("evidence"), list):
                l["evidence"] = [e for e in l["evidence"] if not isinstance(e, str) or e in src]
    return answer, unknown
