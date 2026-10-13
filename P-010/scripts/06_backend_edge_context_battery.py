#!/usr/bin/env python3
"""P-010 — confirm the PUBLIC edge (backend /assistant/chat relay) for context mgmt:
  * the 20-message / 2000-char caps are enforced at the entry point (not just ai-engine)
  * the relay is a STATELESS pass-through: it forwards exactly the client's messages
    and injects NO server-side conversation history (no cross-request memory)

Full chain exercised: backend NestJS :4000  ->  ai-engine :8001  ->  mock LLM :8899.
Guest quota is per-IP (2/24h) with TRUST_PROXY=1, so each request uses a fresh spoofed
X-Forwarded-For to avoid the quota. Imports nothing from the repo. Run with python3 -I.
"""
import json
import time
import urllib.error
import urllib.request

BACKEND = "http://127.0.0.1:4000/api/v1/assistant/chat"
MOCK_LLM = "http://127.0.0.1:8899"
results = []
_ipn = [0]


def _req(method, url, body=None, headers=None, timeout=40):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), int((time.monotonic() - t0) * 1000)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), int((time.monotonic() - t0) * 1000)
    except Exception as e:  # noqa: BLE001
        return 0, f"ERR {type(e).__name__}: {e}", int((time.monotonic() - t0) * 1000)


def edge_chat(messages, locale="vi"):
    _ipn[0] += 1
    ip = f"198.51.100.{_ipn[0] % 250 + 1}"  # fresh IP each call -> stays under guest quota
    return _req("POST", BACKEND, {"messages": messages, "locale": locale}, headers={"X-Forwarded-For": ip})


def llm_stats():
    s, t, _ = _req("GET", MOCK_LLM + "/_stats")
    return json.loads(t) if s == 200 else {}


def reset():
    _req("POST", MOCK_LLM + "/_reset")


def rec(tid, title, inp, http, out, ms, verdict, note=""):
    r = {"id": tid, "title": title, "input": inp, "http": http, "ms": ms,
         "verdict": verdict, "note": note, "output_excerpt": (str(out) or "")[:500]}
    results.append(r)
    print(f"[{tid}] {verdict}  http={http} {ms}ms  {title}")
    return r


# E1 — relay is a stateless pass-through (forwards exactly client messages, no injected memory)
reset()
convo = [
    {"role": "user", "content": "Lượt 1 từ khách"},
    {"role": "assistant", "content": "Trả lời 1"},
    {"role": "user", "content": "Lượt 2 từ khách"},
]
s, out, ms = edge_chat(convo)
st = llm_stats().get("history", [{}])[-1]
roles = st.get("roles", [])
expected = ["system", "user", "assistant", "user"]
rec("E1", "Backend relay is stateless: forwards exactly client messages, adds no history",
    "guest sends a 3-message conversation through the public edge",
    s, {"model_saw_roles": roles, "n": st.get("n_messages")}, ms,
    "STATELESS-PASSTHROUGH" if s == 200 and roles == expected else f"unexpected roles={roles}",
    "The model received system + exactly the client's 3 messages (no server-stored turns prepended). "
    "The backend keeps NO conversation memory; multi-turn memory is entirely client-supplied. "
    "Positive side: no cross-user conversation leakage at the server.")

# E2 — edge enforces the 20-message cap (20 ok, 21 -> 400, LLM not called for 21)
reset()
msgs20 = []
for _ in range(10):
    msgs20.append({"role": "assistant", "content": "ack"})
    msgs20.append({"role": "user", "content": "hỏi"})
s20, _, ms20 = edge_chat(msgs20)
before = llm_stats().get("calls", 0)
msgs21 = [{"role": "user", "content": "x"}] + msgs20
s21, out21, ms21 = edge_chat(msgs21)
after = llm_stats().get("calls", 0)
rec("E2", "Public edge enforces 20-message cap (reject, not window)",
    "edge receives 20 then 21 messages",
    {"n20": s20, "n21": s21}, out21, ms20 + ms21,
    "ENFORCED (20->200, 21->400, no truncation)" if s20 == 200 and s21 == 400 and after == before else f"unexpected {s20}/{s21}",
    "class-validator ArrayMaxSize(20) at AssistantChatDto rejects >20 messages with 400 before relaying; "
    f"LLM not invoked for the over-cap request (calls {before}->{after}).")

# E3 — edge enforces the 2000-char per-message cap
reset()
sok, _, _ = edge_chat([{"role": "user", "content": "A" * 2000}])
sbad, outbad, _ = edge_chat([{"role": "user", "content": "A" * 2001}])
rec("E3", "Public edge enforces 2000-char per-message cap",
    "edge receives a 2000 then 2001 char message",
    {"len2000": sok, "len2001": sbad}, outbad, 0,
    "ENFORCED (2000->200, 2001->400)" if sok == 200 and sbad == 400 else f"unexpected {sok}/{sbad}",
    "MaxLength(2000) at AssistantMessageDto. Hard input cap at the edge == ai-engine cap.")

out_path = "/home/hieubt15/Documents/demo-review-cohort4/cohort4-security-review/P-010/evidences/11_backend_edge_context_battery.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S%z"),
               "chain": "backend:4000 -> ai-engine:8001 -> mock-llm:8899", "results": results}, f,
              ensure_ascii=False, indent=2)
print(f"\nWrote {out_path}")
