---
name: False positive
about: Report benign input that triggers a hit
title: "[FP] <short description>"
labels: false-positive
---

## Input that falsely triggered

```
<paste the benign input>
```

## What fired

<!-- Paste output of `nukon-pi-detect scan --string "<input>"` -->

## Why this is benign

<!-- Context — what were you actually trying to do? -->

## Proposed fix

<!-- Tighten the regex, lower the confidence, or add an exception. -->
