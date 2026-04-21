# Contributing to nukon-pi-detect

Thanks for considering a contribution. This project stays small on purpose, so the bar for additions is higher than usual.

## What we want

**New patterns.** The main way to help. Submit any of:

1. A pattern from a real-world injection you've seen (CVE, red-team writeup, bug bounty report — link it).
2. A variant of an existing pattern that evades our current regex.
3. A test case that causes a false positive on benign text.

## What we don't want

- LLM-based scoring. This library is deterministic by design. ML-based detection belongs in [NukonAI](https://nukonai.com), not here.
- Runtime policy enforcement (blocking, rewriting, logging). This is a scanner, not a guard.
- New runtime dependencies. Zero deps is a feature.
- Patterns without a source. If it's not documented somewhere public, we can't verify it's a real attack pattern vs a theoretical one.

## Submitting a pattern

1. Open an issue first with the attack example and proposed pattern. Saves review time.
2. PR format:
   - Add the pattern to the appropriate list in `nukon_pi_detect/patterns.py`.
   - Use the next free ID in that category (e.g., if CI-012 is the highest classic ID, yours is CI-013).
   - Add at least one positive test case (`test_<category>_*`) and consider one negative test (clean input that shouldn't trigger).
   - Include a one-line mitigation.
3. Run `pytest` — everything should be green.

## Confidence scoring guide

| Confidence | When to use |
|---|---|
| 0.90+ | Pattern is almost never benign (ChatML control tokens, explicit "bypass safety"). |
| 0.70–0.89 | Strong signal but has occasional benign uses (role prefixes, override verbs). |
| 0.50–0.69 | Suspicious in combination but common in benign text alone. |
| <0.50 | Not worth shipping — will cause false positives. |

## Development

```bash
git clone https://github.com/nukonai/nukon-pi-detect
cd nukon-pi-detect
pip install -e ".[dev]"
pytest
```

## Code of conduct

Be decent. Disagreements are fine, abuse isn't.
