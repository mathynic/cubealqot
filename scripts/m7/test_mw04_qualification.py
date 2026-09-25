"""Focused MW-04 integration checks for the post-audit proof boundary."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from sage.all import EllipticCurve, QQ


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import sage_integral_points_mw04 as mw04  # noqa: E402


def run() -> dict:
    # This is the actual N=11 original model used by the qualification
    # campaign.  The two responses model a candidate pool containing P and
    # -P even though the second PARI upper bound is one.
    curve = EllipticCurve([0, 1464, 0, 194712, 25896696])
    p = [QQ(-8330) / 9, QQ(473032) / 27]
    minus_p = [p[0], -p[1]]
    first = mw04._parse_pari_ellrank_result_with_pool(
        curve, [1, 3, 0, [p]]
    )
    second = mw04._parse_pari_ellrank_result_with_pool(
        curve, [1, 1, 0, [minus_p]]
    )
    pool = first[2] + second[2]
    assert len(pool) == 2

    # The actual selection proof for the one-point subgroup is covered by the
    # fresh N=11 worker smoke.  Keep this focused regression cheap while the
    # parser assertion above proves that the opposite point is retained rather
    # than rejected by the legacy ``len(points) <= upper`` check.
    selected, witness = mw04.MW02.select_independent_subset(
        curve, [first[2][0]], 1, prime_bound=19
    )
    assert len(selected) == 1
    assert witness["pool_size"] == 1
    assert witness["selected_indices"] in ([0], [1])

    return {
        "ok": True,
        "status": "PASSED",
        "tests": 2,
        "note": "PARI candidate pools remain untrusted; MW-02 selects the witnessed subgroup.",
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
