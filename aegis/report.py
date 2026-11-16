"""Results as terminal text, JSON (also the status file other tools read) and one HTML page."""

from __future__ import annotations

import html
import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .checks import STATUSES, Result, score

# status names, not passwords
MARK = {"pass": "✓", "warn": "!", "fail": "✗", "info": "i", "unknown": "?"}  # nosec B105
COLOR = {"pass": "32", "warn": "33", "fail": "31", "info": "36", "unknown": "90"}  # nosec B105
ORDER = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}  # nosec B105
SEV = {"high": 0, "medium": 1, "low": 2}


def ordered(results: list[Result]) -> list[Result]:
    return sorted(results, key=lambda r: (ORDER[r.status], SEV[r.severity]))


def counts(results: list[Result]) -> dict[str, int]:
    return {s: sum(r.status == s for r in results) for s in STATUSES}


def verdict(value: int | None) -> str:
    if value is None:
        return "no score"
    return "good" if value >= 85 else "fair" if value >= 60 else "weak"


def to_json(results: list[Result]) -> dict:
    s = score(results)
    return {"version": __version__, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "score": s, "verdict": verdict(s), "counts": counts(results),
            "checks": [asdict(r) for r in ordered(results)]}


def write_status(results: list[Result], path: Path) -> None:
    """For dashboards such as Olympos. Holds what the JSON output holds: no file contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(to_json(results), indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def text(results: list[Result], color: bool = True, fixes: bool = True) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s
    s = score(results)
    n = counts(results)
    out = [c("1", f"Aegis {__version__}") + f": {s if s is not None else '–'}/100 ({verdict(s)}) · "
           + " · ".join(f"{n[k]} {k}" for k in STATUSES if n[k]), ""]
    for r in ordered(results):
        out.append(f"  {c(COLOR[r.status], MARK[r.status])} {r.title:<36} {r.summary}")
        if r.status in ("fail", "warn"):
            for d in r.details[:6]:
                out.append(c("90", f"      · {d}"))
            if fixes:
                for line in r.fix:
                    out.append(("      " + c("36", line)) if line.startswith("$ ") else c("90", f"      {line}"))
    open_ids = [r.id for r in ordered(results) if r.status in ("fail", "warn")]
    if open_ids:
        out += ["", c("90", "aegis explain <id> tells why a check matters: " + ", ".join(open_ids))]
    return "\n".join(out).rstrip() + "\n"


def explain(r: Result) -> str:
    lines = [f"{r.title} [{r.id}] · {r.severity} · {r.status}", "", r.summary, ""]
    lines += [f"  · {d}" for d in r.details]
    lines += ["", "Why it matters", "  " + r.why]
    if r.fix:
        lines += ["", "How to fix it"] + [f"  {f}" for f in r.fix]
    return "\n".join(lines) + "\n"


CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--text:#16181d;--muted:#5d6472;--line:#e3e6ec;--pass:#1f8a4c;--warn:#b26b00;
--fail:#c62f2f;--info:#2667b5;--unknown:#6b7280;--code:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--panel:#171b24;--text:#e6e9ef;--muted:#9aa3b5;--line:#262c3a;
--pass:#4ade80;--warn:#fbbf24;--fail:#f87171;--info:#7aa7ff;--unknown:#8b93a7;--code:#1e2431}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:920px;margin:0 auto;padding:28px 16px 48px}h1{font-size:22px;margin:0}
.head{display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:22px}
.score{font:700 44px/1 ui-monospace,monospace}.sub{color:var(--muted);font-size:13px}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-left:auto}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:12px;background:var(--panel)}
details{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;
margin:10px 0;padding:0 16px}summary{cursor:pointer;padding:12px 0;display:flex;gap:12px;align-items:baseline;list-style:none}
summary::-webkit-details-marker{display:none}.st{font:700 12px ui-monospace,monospace;color:var(--c);min-width:58px;text-transform:uppercase}
.t{font-weight:600;min-width:15em}.s{color:var(--muted)}h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px}
pre{background:var(--code);border-radius:6px;padding:8px 10px;overflow-x:auto;font-size:13px;margin:4px 0}
ul{margin:4px 0 10px;padding-left:1.2em}.pass{--c:var(--pass)}.warn{--c:var(--warn)}.fail{--c:var(--fail)}
.info{--c:var(--info)}.unknown{--c:var(--unknown)}p{margin:4px 0 12px}footer{color:var(--muted);font-size:12px;margin-top:24px}
@media (max-width:640px){summary{flex-wrap:wrap;gap:4px 12px}.t{min-width:0}}
"""


def to_html(results: list[Result], title: str = "Aegis report") -> str:
    e = html.escape
    s = score(results)
    n = counts(results)
    rows = []
    for r in ordered(results):
        body = []
        if r.details:
            body.append("<ul>" + "".join(f"<li>{e(d)}</li>" for d in r.details) + "</ul>")
        body.append(f"<h3>Why it matters</h3><p>{e(r.why)}</p>")
        if r.fix and r.status in ("fail", "warn", "unknown"):
            body.append("<h3>How to fix it</h3>")
            for line in r.fix:
                body.append(f"<pre>{e(line[2:])}</pre>" if line.startswith("$ ") else f"<p>{e(line)}</p>")
        rows.append(f'<details class="{r.status}"{" open" if r.status == "fail" else ""}><summary>'
                    f'<span class="st">{r.status}</span><span class="t">{e(r.title)}</span>'
                    f'<span class="s">{e(r.summary)}</span></summary>{"".join(body)}</details>')
    pills = "".join(f'<span class="pill {k}">{n[k]} {k}</span>' for k in STATUSES if n[k])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>
<div class="head"><div><div class="score">{s if s is not None else "–"}<span class="sub">/100</span></div>
<div class="sub">{verdict(s)}</div></div><div><h1>{e(title)}</h1>
<div class="sub">Aegis {__version__} · {time.strftime("%Y-%m-%d %H:%M")}</div></div><div class="counts">{pills}</div></div>
{"".join(rows)}
<footer>Aegis only reads: nothing on this computer was changed. Checks marked unknown need root or a tool
that is not installed; they do not count in the score.</footer></main></body></html>
"""
