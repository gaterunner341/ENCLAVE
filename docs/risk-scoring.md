# How risk is scored

Two numbers come out of ENCLAVE, and both are worth being able to explain to
somebody who is going to act on them.

## A finding's weight

```
severity band  ×  asset criticality  ×  disposition residual  ×  age factor
```

**Severity band.** Critical 40, high 20, medium 6, low 1.5, informational 0. The
gaps are deliberately wide: ten low findings should not read as worse than one
critical, because they are not.

**Asset criticality.** Mission critical ×1.6, high ×1.3, moderate ×1.0, low
×0.7. The same unpatched service is not the same risk on a payment processor and
on a lab workstation.

**Disposition residual.** A decision somebody recorded changes what the finding
still costs: open ×1, in progress ×0.75, mitigated ×0.3, risk accepted ×0.15,
remediated and false positive ×0. An accepted risk is deliberately not zero. It
is a decision, not a fix, and it should keep showing up.

**Age factor.** 1 until the finding passes the remediation target for its
severity, then it grows, stopping at double weight. An ageing backlog should be
visible without letting it dominate the number.

Default remediation targets, in days from first seen:

| Severity | Target |
|---|---|
| Critical | 15 |
| High | 30 |
| Medium | 90 |
| Low | 180 |

A due date set by hand on a finding overrides the default for that finding.

## An enclave's index

Finding weights are summed, multiplied by the enclave's categorisation (high
×1.5, moderate ×1.2, low ×1.0), divided by the asset count, and put through a
logarithmic curve onto 0 to 100.

Two properties make the number usable:

**It is comparable across sizes.** Dividing by asset count means a twelve-host
enclave and a four-hundred-host one with the same problem per machine land in
the same place, so they can sit in one table and be ranked honestly.

**It does not saturate.** Raw scores span orders of magnitude across an estate.
A linear index would put every enclave with a real backlog at 100 and stop
distinguishing between them. Roughly 20 points of weight per asset — one
un-aged high finding on a moderate-criticality host — lands near 50.

Bands: 75 and above critical, 50 high, 25 moderate, above 0 low, 0 clean.

## What the index is not

It is a triage aid, not a measurement. It says which enclave to look at first.
It does not say how likely a breach is, and it should never be the only number
in a report — the finding counts, the ages, and the baseline coverage all say
things it cannot.

## The risk register

Separately from finding scores, the risk register carries entries scored on the
conventional five-by-five likelihood-by-impact grid, banded very low through
very high. That is the right shape for the things a scanner will never see: a
missing agreement, an unfunded remediation, a compensating control somebody has
to own.

A finding that will be patched next Tuesday does not need an entry. One that
needs a waiver, a compensating control, funding, or a date somebody has to
answer for does. Entries carry control references, so an accepted risk shows up
against the control it weakens rather than disappearing into a spreadsheet.
