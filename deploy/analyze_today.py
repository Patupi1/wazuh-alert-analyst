#!/usr/bin/env python3
"""Homelab deployment: analyse the last 24 h of real Wazuh alerts with the fine-tuned model.

Runs on the Wazuh box (stdlib only). Reads the indexer with the read-only reporting login from
~/.config/alert-report/env, groups alerts into the batch schema the model was trained on
(time, agent, rule, level, description, n, src_ip, user, path, url, log), asks Ollama with the
same system prompt as training, and prints the model's JSON. Nothing leaves the machine.

The answer then goes through deterministic checks (postprocess.py, copied next to this file):
  - escalation: a successful SSH login (5715) from an address that is brute-forcing (5710/5712) is
    critical, and a needs_a_look item names that login, whatever the model said
  - evidence check: IPs, paths and hosts in the answer that are not in the batch are removed from
    evidence lists and listed as unverified
  - the rule-based injection screen (AI_TEXT) runs on the batch independently of the model

  analyze_today.py [--model NAME] [--hours 24] [--max-entries 25] [--dry-run] [--json]

triage() is the entry point for alert-report.py; it never raises.
"""
import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prompt import SYSTEM, user_message  # noqa: E402  (copy prompt.py next to this file)
from postprocess import escalate, evidence_check  # noqa: E402  (copy postprocess.py next to this file)

DEFAULT_MODEL = "hf.co/Yusheng88/tiny-aya-wazuh-analyst-GGUF:Q4_K_M"
# host names the model saw in training; it is most likely to invent these
TRAINING_HOSTS = ["web-01", "web-02", "db-01", "app-01", "nas", "jump", "ci-runner", "mail", "dns-01",
                  "media", "backup", "laptop-kai", "laptop-mira", "pihole", "k8s-node-1", "git-01"]

ENV = Path("~/.config/alert-report/env").expanduser()
AI_TEXT = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|system override|as an ai|ai assistant|assistant[:,]|"
                     r"<\|im_start\|>|<\|START_OF_TURN_TOKEN\|>|new instructions|respond only with", re.I)


def cfg():
    c = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            c[k.strip()] = v.strip().strip("\"'")
    return c


def indexer(c, hours):
    user = c.get("INDEXER_USER") or c.get("ES_USER") or "alertreport"
    pw = c.get("INDEXER_PASSWORD") or c.get("ES_PASSWORD") or c.get("INDEXER_PASS")
    url = (c.get("INDEXER_URL") or "https://127.0.0.1:9200") + "/wazuh-alerts-*/_search"
    # highest levels first so a noisy day (tens of thousands of FIM events) cannot push the
    # few important alerts out of the fetch window
    q = {"size": 5000, "track_total_hits": True, "sort": [{"rule.level": "desc"}, {"timestamp": "asc"}],
         "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "data.srcip", "data.srcuser",
                     "data.dstuser", "data.url", "syscheck.path", "syscheck.event", "full_log"],
         "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}}}
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(url, data=json.dumps(q).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()})
    res = json.load(urllib.request.urlopen(req, context=ctx, timeout=60))["hits"]
    return [h["_source"] for h in res["hits"]], res["total"]["value"]


def shorten(s, n=160):
    s = re.sub(r"\s+", " ", s or "").strip()
    return s[:n]


def to_batch(hits, total, hours, max_entries):
    """Group alerts like the training data: one entry per (agent, rule, source, user, path/url) with a
    repeat count. Low-level file-integrity events (level < 10, typically package upgrades) are
    collapsed per directory so one update does not become a hundred entries."""
    groups = defaultdict(lambda: {"n": 0, "paths": set()})
    agents = {}
    for h in hits:
        rule, agent, data, sc = h.get("rule", {}), h.get("agent", {}), h.get("data", {}), h.get("syscheck", {})
        user = data.get("dstuser") or data.get("srcuser")
        path = sc.get("path")
        pkey = path if (path is None or rule.get("level", 0) >= 10) else os.path.dirname(path)
        key = (agent.get("name"), rule.get("id"), data.get("srcip"), user, pkey, data.get("url"))
        g = groups[key]
        if g["n"] == 0:
            g.update({"time": h["timestamp"][11:16], "agent": agent.get("name"), "rule": str(rule.get("id")),
                      "level": rule.get("level"), "description": rule.get("description")})
            for k, v in (("src_ip", data.get("srcip")), ("user", user), ("event", sc.get("event")), ("url", data.get("url")),
                         ("log", shorten(h.get("full_log"), 120) if rule.get("level", 0) >= 5 and not path else None)):
                if v:
                    g[k] = v
        if path:
            g["paths"].add(path)
        g["n"] += 1
        agents[agent.get("name")] = agent.get("ip", "")
    entries = []
    for g in groups.values():
        paths = sorted(g.pop("paths"))
        if len(paths) == 1:
            g["path"] = paths[0]
        elif paths:
            g["path"] = os.path.dirname(paths[0]) + f"/* ({len(paths)} files)"
        entries.append(g)
    entries = sorted(entries, key=lambda g: (-g["level"], -g["n"]))[:max_entries]
    entries.sort(key=lambda g: g["time"])
    return {"date": max(h["timestamp"] for h in hits)[:10] if hits else "", "window_hours": hours, "agents": agents,
            "total_alerts": total, "alerts": entries}


def lenient_json(text):
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.S)
    try:
        return json.loads(text)
    except Exception:
        i, j = text.find("{"), text.rfind("}")
        if i >= 0 and j > i:
            try:
                return json.loads(text[i:j + 1])
            except Exception:
                return None
    return None


def ask(model, batch, url="http://127.0.0.1:11434"):
    body = {"model": model, "stream": False, "keep_alive": 0, "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 900},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_message(batch)}]}
    req = urllib.request.Request(url + "/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=900))["message"]["content"]


def screen(batch):
    """Rule-based injection screen, independent of the model."""
    return [g for g in batch["alerts"] if AI_TEXT.search(json.dumps(g, ensure_ascii=False))]


def triage(hours=24, max_entries=25, model=None, c=None):
    """Batch -> model -> checks. Returns a dict and never raises; on failure `error` is set and
    `answer` is None, but the rule-based escalation and injection screen still run."""
    r = {"model": None, "answer": None, "severity": None, "notes": [], "unverified": [], "flagged": [],
         "batch": None, "latency_s": None, "error": None, "raw": None}
    try:
        c = c if c is not None else cfg()
        r["model"] = model or c.get("ANALYST_MODEL") or os.environ.get("ANALYST_MODEL") or DEFAULT_MODEL
        hits, total = indexer(c, hours)
        batch = r["batch"] = to_batch(hits, total, hours, max_entries)
        r["flagged"] = screen(batch)
        # training host names that are also ordinary words ("the last backup") are left out of the free-text scan
        hosts = [h for h in TRAINING_HOSTS if h not in ("backup", "mail", "media", "jump")] + [h.strip() for h in c.get("ANALYST_HOSTS", "").split(",") if h.strip()]
        t = time.time()
        try:
            r["raw"] = ask(r["model"], batch, c.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        except Exception as e:
            r["error"] = f"model call failed: {e}"
        r["latency_s"] = round(time.time() - t, 1)
        ans = lenient_json(r["raw"]) if r["raw"] else None
        if r["raw"] and not isinstance(ans, dict):
            r["error"] = "model answer was not JSON"
            ans = None
        if ans is None:
            # rule-based floor: the escalation still applies without a model answer
            ans_rule, notes = escalate(batch, {"severity": None, "prompt_injection": bool(r["flagged"]),
                                               "summary": "", "needs_a_look": [], "routine": [], "next_step": ""})
            if notes:
                r["severity"], r["notes"] = "critical", notes
                r["rule_items"] = ans_rule["needs_a_look"]
            return r
        ans, r["notes"] = escalate(batch, ans)
        ans, r["unverified"] = evidence_check(batch, ans, hosts)
        r["answer"], r["severity"] = ans, ans.get("severity")
    except Exception as e:
        r["error"] = r["error"] or f"{type(e).__name__}: {e}"
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help=f"default: ANALYST_MODEL from the env file, else {DEFAULT_MODEL}")
    ap.add_argument("--json", action="store_true", help="print the full triage() result as JSON")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--max-entries", type=int, default=25)
    ap.add_argument("--dry-run", action="store_true", help="print the batch, do not call the model")
    a = ap.parse_args()
    if a.dry_run:
        hits, total = indexer(cfg(), a.hours)
        batch = to_batch(hits, total, a.hours, a.max_entries)
        print(json.dumps(batch, indent=1, ensure_ascii=False))
        print(f"\n{total} alerts ({len(hits)} fetched) -> {len(batch['alerts'])} entries, "
              f"{len(json.dumps(batch, separators=(',', ':')))} chars; rule-based injection flags: {len(screen(batch))}")
        return
    r = triage(a.hours, a.max_entries, a.model)
    if a.json:
        print(json.dumps(r, indent=1, ensure_ascii=False))
        return
    print(f"model {r['model']}  ({r['latency_s']} s)")
    if r["error"]:
        print("ERROR:", r["error"])
        if r["raw"]:
            print(r["raw"])
    if r["answer"] is not None:
        print(json.dumps(r["answer"], indent=1, ensure_ascii=False))
    for n in r["notes"]:
        print("[escalation rule]", n)
    if r["unverified"]:
        print("[evidence check] not in the batch:", ", ".join(r["unverified"]))
    if r["flagged"]:
        print(f"[rule-based screen] {len(r['flagged'])} entr{'y' if len(r['flagged']) == 1 else 'ies'} contain text aimed at an AI; shown as data:")
        for g in r["flagged"]:
            print("  ", json.dumps(g, ensure_ascii=False)[:200])

if __name__ == "__main__":
    main()
