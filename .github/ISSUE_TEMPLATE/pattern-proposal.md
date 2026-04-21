---
name: New pattern proposal
about: Propose a new prompt-injection pattern
title: "[pattern] <short description>"
labels: pattern-proposal
---

## Attack example

<!-- A real string that demonstrates the attack. Paste verbatim. -->

```
<paste the attack string here>
```

## Source

<!-- Where did you see this? CVE, bug bounty writeup, red-team dataset, blog post. Link required. -->

## Why current patterns miss it

<!-- Run `nukon-pi-detect scan --string "<attack>"` and paste output. If we already catch it, the issue can be closed. -->

## Proposed pattern

- **Category**: classic / jailbreak / delimiter / unicode / indirect
- **Proposed ID**: (next free in category)
- **Regex**: `...`
- **Confidence**: 0.XX (see CONTRIBUTING.md scoring guide)
- **Mitigation**: (one line)

## False positive check

<!-- Run the proposed regex against common benign text. Any false hits? -->
