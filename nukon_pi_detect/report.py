"""
HTML report renderer.

Takes a ScanResult and produces a single self-contained HTML page
(no external assets, no JS dependencies) suitable for CI artifacts,
PR comments, or dropping into a report bundle.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .detector import DECISION_CLEAN, DECISION_MALICIOUS, DECISION_SUSPICIOUS, ScanResult


_DECISION_STYLE = {
    DECISION_CLEAN:      ("#0a7f3f", "#e8f5ec", "✓"),
    DECISION_SUSPICIOUS: ("#b8860b", "#fff8e1", "!"),
    DECISION_MALICIOUS:  ("#c23616", "#fdecea", "✗"),
}

_CATEGORY_LABEL = {
    "classic":   "Classic injection",
    "jailbreak": "Jailbreak",
    "delimiter": "Delimiter escape",
    "unicode":   "Unicode smuggling",
    "indirect":  "Indirect injection",
}


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def render_html(result: ScanResult, source_label: str = "input") -> str:
    fg, bg, glyph = _DECISION_STYLE[result.decision]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Group hits by category for the summary
    cat_counts: dict[str, int] = {}
    for h in result.hits:
        cat_counts[h.category] = cat_counts.get(h.category, 0) + 1

    cat_rows = "".join(
        f'<tr><td>{_esc(_CATEGORY_LABEL.get(c, c))}</td><td class="num">{n}</td></tr>'
        for c, n in sorted(cat_counts.items(), key=lambda x: -x[1])
    ) or '<tr><td colspan="2" class="empty">No categories triggered.</td></tr>'

    hit_rows = "".join(_render_hit_row(h) for h in result.hits) or \
        '<tr><td colspan="5" class="empty">No patterns matched — input looks clean.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>nukon-pi-detect scan report</title>
<style>
  :root {{ --fg:#1a1a1a; --muted:#666; --border:#e5e5e5; --bg:#fafafa; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
         color: var(--fg); background: var(--bg); margin: 0; padding: 2rem; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  h1 {{ font-size: 1.3rem; margin: 0; font-weight: 600; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }}
  .verdict {{ display: inline-flex; align-items: center; gap: 0.5rem;
              background: {bg}; color: {fg}; padding: 0.5rem 1rem;
              border-radius: 6px; font-weight: 600; font-size: 1rem;
              border: 1px solid {fg}33; }}
  .verdict .glyph {{ font-size: 1.1rem; }}
  .score {{ margin-left: 0.75rem; color: var(--muted); font-weight: 500; }}
  section {{ background: #fff; border: 1px solid var(--border); border-radius: 8px;
             padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
  section h2 {{ font-size: 0.95rem; margin: 0 0 0.75rem; font-weight: 600;
                text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
  .stat {{ border-left: 3px solid {fg}; padding-left: 0.75rem; }}
  .stat .v {{ font-size: 1.2rem; font-weight: 600; }}
  .stat .k {{ font-size: 0.8rem; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th, td {{ text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border);
            vertical-align: top; }}
  th {{ font-weight: 600; color: var(--muted); font-size: 0.78rem;
        text-transform: uppercase; letter-spacing: 0.03em; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .empty {{ color: var(--muted); font-style: italic; text-align: center; }}
  .pid {{ font-family: ui-monospace, SF Mono, Menlo, monospace;
          font-size: 0.82rem; color: var(--muted); }}
  .conf {{ font-variant-numeric: tabular-nums; }}
  .conf-bar {{ display: inline-block; width: 50px; height: 6px; background: #eee;
               border-radius: 3px; overflow: hidden; margin-right: 0.4rem;
               vertical-align: middle; }}
  .conf-bar > span {{ display: block; height: 100%; background: {fg}; }}
  .snippet {{ font-family: ui-monospace, SF Mono, Menlo, monospace;
              font-size: 0.82rem; background: #f5f5f5; padding: 0.15rem 0.35rem;
              border-radius: 3px; word-break: break-word; }}
  .mitig {{ color: var(--muted); font-size: 0.82rem; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem;
            margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
  footer a {{ color: var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>nukon-pi-detect · scan report</h1>
    <div class="meta">Source: <code>{_esc(source_label)}</code> · Generated {ts}</div>
  </header>

  <section>
    <h2>Verdict</h2>
    <div>
      <span class="verdict"><span class="glyph">{glyph}</span>{result.decision}</span>
      <span class="score">Aggregate score: <strong>{result.score:.2f}</strong></span>
    </div>
  </section>

  <section>
    <h2>Scan stats</h2>
    <div class="stats">
      <div class="stat"><div class="v">{result.input_length}</div><div class="k">Input chars</div></div>
      <div class="stat"><div class="v">{len(result.hits)}</div><div class="k">Pattern hits</div></div>
      <div class="stat"><div class="v">{len(result.categories_hit)}</div><div class="k">Categories</div></div>
      <div class="stat"><div class="v">{result.elapsed_ms:.2f} ms</div><div class="k">Scan time</div></div>
    </div>
  </section>

  <section>
    <h2>Category breakdown</h2>
    <table>
      <thead><tr><th>Category</th><th class="num">Hits</th></tr></thead>
      <tbody>{cat_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Pattern hits</h2>
    <table>
      <thead><tr>
        <th>ID</th><th>Name</th><th>Confidence</th><th>Match</th><th>Mitigation</th>
      </tr></thead>
      <tbody>{hit_rows}</tbody>
    </table>
  </section>

  <footer>
    Generated by <strong>nukon-pi-detect</strong> · Apache 2.0 · No LLM calls, no network, deterministic.<br>
    Need runtime enforcement with audit-grade logs? See
    <a href="https://nukonai.com">NukonAI</a>.
  </footer>
</div>
</body>
</html>
"""


def _render_hit_row(h) -> str:
    conf_pct = int(h.confidence * 100)
    return (
        f"<tr>"
        f'<td><span class="pid">{_esc(h.id)}</span><br>'
        f'<span class="pid" style="font-size:0.72rem">{_esc(_CATEGORY_LABEL.get(h.category, h.category))}</span></td>'
        f"<td>{_esc(h.name)}</td>"
        f'<td class="conf"><span class="conf-bar"><span style="width:{conf_pct}%"></span></span>'
        f"{h.confidence:.2f}</td>"
        f'<td><span class="snippet">{_esc(h.snippet)}</span></td>'
        f'<td class="mitig">{_esc(h.mitigation)}</td>'
        f"</tr>"
    )
