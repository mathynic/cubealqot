# Candidate job inputs

This directory retains candidate-jobs.json, a set of 171 fixed-cofactor
research candidates derived from saved nonsquare-survivor records. Each job
contains a cofactor $N$ and its prime factorization.

These are search inputs, not theorem admissions. They make no claim that a
family has no solutions or that a candidate will be easy to prove.

The candidate records do not include $A$, $D$, or the curve coefficients.
The Mordell–Weil qualification runner needs those values and hydrates
incomplete records from ranked-cofactors.json, which is not included in this
repository snapshot. The tracked candidate list also omits N=39, 65, and 133
from the qualification runner's default selection. A fresh clone needs a
complete candidate file or fallback data for its selected cases.
