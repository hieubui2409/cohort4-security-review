"""P-143 SECURITY TEST — in-process mock LLM (client layer).

Loaded automatically by CPython at interpreter startup because this directory is
first on PYTHONPATH (site.py imports `sitecustomize`). It patches the OpenAI SDK
*client methods* that the app calls, so NO network request ever leaves the
process and NO repo source is modified. Every call is logged (the exact prompt
the app built) to SECTEST_LLM_LOG, and a minimal valid response is returned so
the pipeline proceeds (and the metered gateway caches the answer).

This file imports nothing from the P-143 repo.
"""
import json
import os
import threading
import time
import typing

LOG = os.environ.get("SECTEST_LLM_LOG", "/sectest/out/llm_calls.jsonl")
_lock = threading.Lock()
_counter = {"n": 0}


def _log(rec):
    with _lock:
        _counter["n"] += 1
        rec["seq"] = _counter["n"]
        rec["ts"] = round(time.time(), 3)
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        except Exception as e:  # never break the app because of logging
            print(f"[sectest-shim] log error: {e}", flush=True)


def _sanitize(obj):
    """Deep-copy for JSON, replacing base64 image blobs with a short marker and
    their length, so the log shows structure/text but not megabytes of base64."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("image_url",) and isinstance(v, str) and v.startswith("data:"):
                out[k] = f"<IMAGE data-url len={len(v)}>"
            elif k == "image_url" and isinstance(v, dict):
                u = v.get("url", "")
                out[k] = {"url": f"<IMAGE data-url len={len(u)}>" if isinstance(u, str) else u,
                          **{kk: vv for kk, vv in v.items() if kk != "url"}}
            elif k in ("url",) and isinstance(v, str) and v.startswith("data:"):
                out[k] = f"<IMAGE data-url len={len(v)}>"
            else:
                out[k] = _sanitize(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_sanitize(x) for x in obj]
    return obj


def _char_len(obj):
    try:
        return len(json.dumps(obj, ensure_ascii=False, default=str))
    except Exception:
        return 0


# ---------- minimal valid pydantic instance builder (for responses.parse) ----------
def _min_value(ann):
    try:
        from pydantic import BaseModel
    except Exception:
        BaseModel = None
    import enum as _enum

    origin = typing.get_origin(ann)
    args = typing.get_args(ann)
    # Optional / Union
    try:
        import types as _t
        is_union = origin is typing.Union or (hasattr(_t, "UnionType") and origin is _t.UnionType)
    except Exception:
        is_union = origin is typing.Union
    if is_union:
        if type(None) in args:
            return None
        return _min_value(args[0])
    if origin in (list, tuple, set, frozenset) or origin is typing.Sequence:
        return []
    if origin in (dict,) or origin is typing.Mapping:
        return {}
    if isinstance(ann, type) and BaseModel is not None and issubclass(ann, BaseModel):
        return _min_dict(ann)
    if isinstance(ann, type) and issubclass(ann, _enum.Enum):
        return list(ann)[0].value
    if ann is str:
        return "0"           # a string that also parses as a number/decimal if needed
    if ann is int:
        return 0
    if ann is float:
        return 0.0
    if ann is bool:
        return False
    return None


def _min_dict(model):
    out = {}
    for name, field in model.model_fields.items():
        try:
            required = field.is_required()
        except Exception:
            required = True
        if required:
            out[name] = _min_value(field.annotation)
    return out


def _build_instance(schema):
    try:
        return schema.model_validate(_min_dict(schema))
    except Exception as e:
        print(f"[sectest-shim] could not build {getattr(schema,'__name__',schema)}: {e}", flush=True)
        try:
            return schema.model_construct()
        except Exception:
            return None


# ---------- fake response objects ----------
class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _usage_responses(in_chars, out_chars=40):
    return _NS(input_tokens=max(1, in_chars // 4), output_tokens=max(1, out_chars // 4))


def _usage_chat(in_chars, out_chars=40):
    return _NS(prompt_tokens=max(1, in_chars // 4), completion_tokens=max(1, out_chars // 4),
               total_tokens=max(1, in_chars // 4) + max(1, out_chars // 4))


class _ParseResp:
    def __init__(self, parsed, usage):
        self.output_parsed = parsed
        self.usage = usage


class _CreateResp:
    def __init__(self, output_text, usage):
        self.output_text = output_text
        self.usage = usage
        self.status = "completed"
        self.incomplete_details = None


class _Choice:
    def __init__(self, content, finish_reason="stop"):
        self.message = _NS(content=content, role="assistant")
        self.finish_reason = finish_reason
        self.index = 0


class _ChatResp:
    def __init__(self, content, usage):
        self.choices = [_Choice(content)]
        self.usage = usage


# ---------- the patch ----------
try:
    import openai  # noqa: F401
    from openai.resources.responses.responses import AsyncResponses
    from openai.resources.chat.completions.completions import AsyncCompletions

    async def _mock_parse(self, *args, **kwargs):
        model = kwargs.get("model")
        inp = kwargs.get("input")
        text_format = kwargs.get("text_format")
        san = _sanitize(inp)
        _log({"call": "responses.parse", "model": model,
              "text_format": getattr(text_format, "__name__", str(text_format)),
              "input_chars": _char_len(inp), "input": san})
        parsed = _build_instance(text_format) if isinstance(text_format, type) else None
        return _ParseResp(parsed, _usage_responses(_char_len(inp)))

    async def _mock_create(self, *args, **kwargs):
        model = kwargs.get("model")
        inp = kwargs.get("input")
        text = kwargs.get("text")
        san = _sanitize(inp)
        _log({"call": "responses.create", "model": model,
              "input_chars": _char_len(inp),
              "text_format_keys": list((text or {}).get("format", {}).keys()) if isinstance(text, dict) else None,
              "input": san})
        # vision reader expects a JSON object it can map (to_read tolerates missing keys)
        return _CreateResp('{"lines": []}', _usage_responses(_char_len(inp), out_chars=20))

    async def _mock_chat(self, *args, **kwargs):
        model = kwargs.get("model")
        msgs = kwargs.get("messages")
        san = _sanitize(msgs)
        _log({"call": "chat.completions.create", "model": model,
              "input_chars": _char_len(msgs), "messages": san})
        return _ChatResp('{}', _usage_chat(_char_len(msgs)))

    AsyncResponses.parse = _mock_parse
    AsyncResponses.create = _mock_create
    AsyncCompletions.create = _mock_chat
    print(f"[sectest-shim] openai client methods patched; log -> {LOG}", flush=True)
except Exception as e:  # pragma: no cover
    print(f"[sectest-shim] FAILED to patch openai: {e}", flush=True)
