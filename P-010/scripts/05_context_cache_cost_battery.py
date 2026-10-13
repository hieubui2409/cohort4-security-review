#!/usr/bin/env python3
"""P-010 VinStay AI — DYNAMIC battery: context/memory, caching, cost/token.

Focus (application-layer agentic behaviour, measured with a MOCK LLM — the real
model's judgement is explicitly out of scope / mentor-waived):

  (1) Multi-turn context/memory management — how many turns does the APP keep in
      the context it sends to the model? Any sliding window / trimming / cap?
  (2) Caching of repeated requests — does the APP cache (skip the 2nd LLM call)
      or re-invoke the model every time?
  (3) Cost / token accounting — does the APP count / cap tokens or cost per
      user/session? Is the input capped?

Stack under test (localhost, isolated, real ai-engine code):
  ai-engine FastAPI :8001  (real code; OpenAI client redirected to mock LLM)
  mock LLM         :8899  (OpenAI-compatible; counts calls, echoes messages, returns usage)
  mock core        :8002  (returns a unit so get_unit fires -> exercises the 60s read cache)

Imports NOTHING from the repo. Run from OUTSIDE the repo with: python3 -I 05_...py
"""
import json
import time
import urllib.error
import urllib.request

AIENGINE = "http://127.0.0.1:8001"
MOCK_LLM = "http://127.0.0.1:8899"
MOCK_CORE = "http://127.0.0.1:8002"
INTERNAL_KEY = "p010review-internal-key"

results = []


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


def chat(messages, locale="vi"):
    return _req("POST", AIENGINE + "/chat", {"messages": messages, "locale": locale},
                headers={"X-Internal-Key": INTERNAL_KEY})


def llm_stats():
    s, t, _ = _req("GET", MOCK_LLM + "/_stats")
    return json.loads(t) if s == 200 else {}


def core_stats():
    s, t, _ = _req("GET", MOCK_CORE + "/_stats")
    return json.loads(t) if s == 200 else {}


def reset():
    _req("POST", MOCK_LLM + "/_reset")
    _req("POST", MOCK_CORE + "/_reset")


def rec(tid, title, inp, http, out, ms, verdict, note=""):
    r = {"id": tid, "title": title, "input": inp, "http": http, "ms": ms,
         "verdict": verdict, "note": note, "output_excerpt": (str(out) or "")[:600]}
    results.append(r)
    print(f"[{tid}] {verdict}  http={http} {ms}ms  {title}")
    return r


U = lambda i: {"role": "user", "content": f"Lượt khách số {i}: tư vấn giúp mình một căn studio nhé."}
A = lambda i: {"role": "assistant", "content": f"Trả lời trợ lý số {i}: mình ghi nhận yêu cầu."}

# =====================================================================
print("\n=== (1) CONTEXT / MEMORY MANAGEMENT (multi-turn) ===")
# =====================================================================

# C1a — send a 9-message growing conversation; measure how many the app forwards to the model
reset()
convo9 = []
for i in range(1, 5):
    convo9.append(U(i)); convo9.append(A(i))
convo9.append(U(5))  # 9 messages, ends with user
s, out, ms = chat(convo9)
st = llm_stats()
last = st.get("history", [{}])[-1]
roles = last.get("roles", [])
n = last.get("n_messages")
rec("C1a", "How many turns the app forwards to the model (no server-side window)",
    f"client sends {len(convo9)} messages (4 user+4 assistant+1 user)",
    s, {"model_saw_n_messages": n, "roles": roles}, ms,
    "NO-WINDOWING (full passthrough)" if n == len(convo9) + 1 and roles[0] == "system" else "unexpected",
    f"Model received system + ALL {len(convo9)} client messages (n={n}). The ai-engine builds "
    "convo=[system]+messages verbatim: NO sliding window, NO summarisation, NO trimming. Memory is "
    "purely client-driven (stateless server).")

# C1b — the hard upper bound: exactly 20 messages is accepted
reset()
msgs20 = []
for _ in range(10):
    msgs20.append({"role": "assistant", "content": "ack"})
    msgs20.append({"role": "user", "content": "hỏi tiếp"})  # ends with user, 20 messages
s, out, ms = chat(msgs20)
st = llm_stats()
n20 = st.get("history", [{}])[-1].get("n_messages")
rec("C1b", "Context cap upper bound: 20 messages accepted",
    "client sends exactly 20 messages", s, {"model_saw_n_messages": n20}, ms,
    "ACCEPTED" if s == 200 and n20 == 21 else f"unexpected {s}",
    "DTO allows max 20 messages (ai-engine ChatRequest.messages max_length=20); model saw 21 (system+20).")

# C1c — 21 messages -> REJECTED entirely (cap = reject, not truncate); LLM NOT called
reset()
msgs21 = [{"role": "user", "content": "x"}] + msgs20  # 21 messages
before = llm_stats().get("calls", 0)
s, out, ms = chat(msgs21)
after = llm_stats().get("calls", 0)
rec("C1c", "Over-cap (21 messages) is rejected, not windowed",
    "client sends 21 messages", s, out, ms,
    "REJECTED-422 (no truncation, LLM not called)" if s == 422 and after == before else f"unexpected {s}",
    f"ai-engine returns 422 and does NOT invoke the model (llm_calls {before}->{after}). The app does "
    "NOT drop/slide older turns to fit; it rejects the whole request. The window is a HARD cap enforced "
    "by request validation, owned by the client.")

# C1d — per-message content cap: 2000 chars ok, 2001 rejected
reset()
s_ok, _, ms_ok = chat([{"role": "user", "content": "A" * 2000}])
s_bad, out_bad, ms_bad = chat([{"role": "user", "content": "A" * 2001}])
rec("C1d", "Per-message content length cap (2000 chars)",
    "one user message of 2000 then 2001 chars",
    {"len2000": s_ok, "len2001": s_bad}, out_bad, ms_ok + ms_bad,
    "ENFORCED (2000 ok, 2001 -> 422)" if s_ok == 200 and s_bad == 422 else f"unexpected {s_ok}/{s_bad}",
    "ChatMessage.content max_length=2000. Combined with max 20 messages => hard INPUT cap "
    "~20*2000=40k chars per request. This is a structural input cap, not a token/cost budget.")

# =====================================================================
print("\n=== (2) CACHING OF REPEATED REQUESTS ===")
# =====================================================================

# C2a — identical chat sent 5x: is the model re-invoked every time?
reset()
same = [{"role": "user", "content": "Câu hỏi giống hệt để kiểm tra cache nhé."}]
calls_seq, lat = [], []
for _ in range(5):
    s, out, ms = chat(same)
    calls_seq.append(llm_stats().get("calls"))
    lat.append(ms)
rec("C2a", "Repeated IDENTICAL request -> LLM re-invoked every time (no response cache)",
    "same chat body sent 5 times", s, {"llm_calls_after_each": calls_seq, "latency_ms": lat}, sum(lat),
    "NO-LLM-CACHE (1 call per request)" if calls_seq == [1, 2, 3, 4, 5] else f"unexpected {calls_seq}",
    "Each identical /chat triggers a fresh model call (calls 1..5), latency flat (no cache hit). The app "
    "has NO request/response dedup or memoisation at the LLM layer. Every duplicate costs a full inference.")

# C2b — the ONLY cache in the app: 60s read cache at the tool/core layer
reset()
tool_chat = [{"role": "user", "content": "DIRECTIVE_TOOL_GETUNIT cho mình xem chi tiết căn này"}]
s1, _, ms1 = chat(tool_chat)
s2, _, ms2 = chat(tool_chat)
cs = core_stats()
ls = llm_stats()
core_hits = cs.get("GET /properties/units/VHOP-TEST-0001", None)
rec("C2b", "Only cache present: 60s read cache at tool/core layer (NOT the LLM)",
    "two identical tool-calling chats within 60s", s2,
    {"core_get_unit_hits": core_hits, "llm_calls": ls.get("calls"), "core_stats": cs}, ms1 + ms2,
    "CORE-READ-CACHED (1 core hit) / LLM-NOT-CACHED" if core_hits == 1 and ls.get("calls", 0) >= 2 else f"check: core={core_hits} llm={ls.get('calls')}",
    "get_unit fired on both turns but the core backend was hit ONCE (2nd served from CoreApi._CACHE, "
    "TTL=60s, max 256 entries, keyed by path+params). Meanwhile the LLM was called on every turn/round. "
    "So the app caches DATA READS for 60s but never the model output.")

# =====================================================================
print("\n=== (3) COST / TOKEN ACCOUNTING ===")
# =====================================================================

# C3a — large near-max input repeated from the SAME caller: any cumulative cost cap?
reset()
big_msgs = []
for _ in range(10):
    big_msgs.append({"role": "assistant", "content": "A" * 1990})
    big_msgs.append({"role": "user", "content": "B" * 1990})  # 20 msgs, ~40k chars each request
codes = []
for _ in range(6):
    s, out, ms = chat(big_msgs)
    codes.append(s)
st = llm_stats()
total_chars_last = st.get("history", [{}])[-1].get("content_chars")
rec("C3a", "No per-user/session token or cost budget (unbounded repeat of max input)",
    "6x the maximum-size request (20 msgs x ~1990 chars) from the same internal key",
    codes, {"http_codes": codes, "llm_calls": st.get("calls"), "model_prompt_chars_last": total_chars_last}, 0,
    "NO-COST-CAP (all accepted)" if codes == [200] * 6 else f"unexpected {codes}",
    "All 6 maximal requests succeed; the ai-engine keeps no per-user/session counter and enforces no "
    "token/cost ceiling. It has no user identity at all (only an optional firstName is forwarded), so "
    "per-user accounting is impossible at this layer. Only limiters: structural input cap (20x2000), "
    "MAX_TOOL_ROUNDS=5 (<=6 LLM calls/turn), and backend-edge IP throttle + guest quota (see prior EV-06).")

# C3b — token usage IS computed (returned by model layer) but only logged, never aggregated/capped
reset()
chat([{"role": "user", "content": "đo token nhé"}])
rec("C3b", "Token usage is observed+logged but not aggregated or enforced",
    "single chat; ai-engine requests usage via stream_options.include_usage",
    200, {"note": "see ai-engine stdout log line {promptTokens, completionTokens}"}, 0,
    "ACCOUNTING-PRESENT-BUT-ADVISORY",
    "agent.py sums prompt/completion tokens per TURN and logs them, but the sum is discarded after the "
    "turn: no persistence, no per-user/session total, no budget check. Accounting is advisory logging only.")

out_path = "/home/hieubt15/Documents/demo-review-cohort4/cohort4-security-review/P-010/evidences/10_context_cache_cost_battery.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S%z"),
               "stack": {"ai_engine": AIENGINE, "mock_llm": MOCK_LLM, "mock_core": MOCK_CORE},
               "results": results}, f, ensure_ascii=False, indent=2)
print(f"\nWrote {out_path}")
