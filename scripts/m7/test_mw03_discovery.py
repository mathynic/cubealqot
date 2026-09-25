"""MW-03 discovery-driver tests; run in the pinned Sage environment."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sage.all import EllipticCurve, QQ

from discover_mw_points import (
    JOURNAL_SCHEMA_VERSION,
    SCHEDULE_VERSION,
    DiscoveryError,
    append_journal_record,
    canonical_point,
    load_problem,
    load_journal_state,
    make_schedule,
    pending_discovery_ids,
    perform_attempt,
    pending_attempts,
    publish_point_file,
    summarize_discovery_status,
    validate_point_record,
    _ell2cover_with_precision,
    _run_precision_ladder,
)


REQUEST = (
    Path(__file__).resolve().parents[2]
    / "out/m7-pari-qualification/pq02-qualified-20260921/cases/N19/request.json"
)


def run() -> dict:
    problem, curve = load_problem(REQUEST)
    assert problem["n"] == "19"
    point = curve([QQ(-3666), QQ(197412)])
    record = canonical_point(point)
    assert record == {"x": "-3666", "y": "197412"}
    assert validate_point_record(curve, record) == point
    assert validate_point_record(curve, {"x": "-3666", "y": "197413"}) is None

    heegner_request = (
        Path(__file__).resolve().parents[2]
        / "tests/fixtures/m7/mw03_heegner_fixture_request.json"
    )
    heegner_result = perform_attempt(
        heegner_request,
        {"method": "heegner"},
        [],
    )
    assert heegner_result["status"] == "POINT_CANDIDATES"
    assert heegner_result["details"]["analytic_rank_one_hypothesis"] is True
    assert heegner_result["points"]

    cover_request = (
        Path(__file__).resolve().parents[2]
        / "tests/fixtures/m7/mw03_cover_fixture_request.json"
    )
    cover_result = perform_attempt(
        cover_request,
        {"method": "cover", "cover_index": 0, "height_bound": 10},
        [],
    )
    assert cover_result["status"] == "POINT_CANDIDATES"
    assert cover_result["details"]["cover"]["identity_remainder"] == "0"
    assert cover_result["points"]
    assert cover_result["details"]["precision_bits"] in (128, 256, 512)

    # Regression for the installed PARI API: global precision is not enough;
    # the explicit ell2cover keyword must receive the selected value.
    observed_cover_precisions = []

    class FakePariCurve:
        def ell2cover(self, *, precision):
            observed_cover_precisions.append(precision)
            return ["cover"]

    class FakeMinimal:
        def pari_curve(self):
            return FakePariCurve()

    assert _ell2cover_with_precision(FakeMinimal(), 256) == ["cover"]
    assert observed_cover_precisions == [256]

    # The precision retry policy is narrow: only small_norm failures advance
    # the ladder, and the attempted precisions remain replayable evidence.
    attempted_precisions = []

    def simulated_precision_operation(precision):
        attempted_precisions.append(precision)
        if precision < 512:
            raise RuntimeError("bug in small_norm (precision too low)")
        return {"precision": precision}

    ladder_result, ladder_attempts = _run_precision_ladder(
        simulated_precision_operation
    )
    assert ladder_result == {"precision": 512}
    assert attempted_precisions == [128, 256, 512]
    assert [item["status"] for item in ladder_attempts] == [
        "PRECISION_FAILURE", "PRECISION_FAILURE", "SUCCESS"
    ]

    inventory_result = perform_attempt(
        REQUEST,
        {
            "method": "inventory",
            "rank": 2,
            "need_conductor": False,
            "max_cover_count": 2,
        },
        [],
    )
    assert inventory_result["status"] == "INVENTORY_COMPLETE"
    assert inventory_result["details"]["cover_count"] >= 1

    with tempfile.TemporaryDirectory(prefix="mw03-test-") as directory:
        root = Path(directory)
        output = root / "points.json"
        publish_point_file(output, problem, [record])
        written = json.loads(output.read_text(encoding="utf-8"))
        assert written["kind"] == "m7_mw_point_candidates"
        assert written["schema_version"] == 1
        assert written["points"] == [record]

        schedule = make_schedule(rank=2, cover_count=2, conductor=19)
        ids = [item["attempt_id"] for item in schedule]
        assert ids == [item["attempt_id"] for item in make_schedule(rank=2, cover_count=2, conductor=19)]
        assert len(ids) == len(set(ids))
        assert all("complete" not in item for item in schedule)
        assert any(item["method"] == "cover" for item in schedule)
        open_rank_schedule = make_schedule(rank=None, cover_count=2, conductor=None)
        assert any(item["method"] == "cover" for item in open_rank_schedule)
        capped = make_schedule(rank=1, cover_count=0, conductor=10**13)
        assert capped[-1]["skip_status"] == "SKIPPED_CONDUCTOR_POLICY"

        journal = root / "journal.jsonl"
        identity = {"n": problem["n"], "curve_coefficients": problem["curve_coefficients"]}
        append_journal_record(journal, {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": ids[0],
            "status": "NO_NEW_POINTS",
            "points": [],
        })
        append_journal_record(journal, {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": ids[1],
            "status": "INTERRUPTED",
            "points": [],
        })
        state = load_journal_state(journal, identity)
        assert state[ids[0]]["status"] == "NO_NEW_POINTS"

        legacy_journal = root / "legacy-journal.jsonl"
        append_journal_record(legacy_journal, {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": "mw03-discovery-v1",
            "identity": identity,
            "attempt_id": "legacy-attempt",
            "status": "NO_NEW_POINTS",
            "points": [],
        })
        legacy_state = load_journal_state(legacy_journal, identity)
        assert legacy_state["legacy-attempt"]["status"] == "NO_NEW_POINTS"

        pending_ids = {item["attempt_id"] for item in pending_attempts(schedule, state)}
        assert ids[0] not in pending_ids
        assert ids[1] in pending_ids

        # A retained candidate must not mask an unfinished retryable attempt.
        # This is the resume regression: POINT_CANDIDATES is not schedule
        # completion, and therefore cannot be allowed to suppress TIMEOUT.
        rank_probe_id = "rank-probe-e0-s1-p128"
        state[rank_probe_id] = {
            "status": "RANK_PROVEN",
            "details": {"lower_bound": 2, "upper_bound": 2},
        }
        pending = pending_discovery_ids(state, schedule, rank_probe_id, 2, "inventory-rank-one")
        assert ids[1] in pending
        assert "inventory-rank-one" in pending
        assert summarize_discovery_status(
            [
                {"status": "POINT_CANDIDATES"},
                {"status": "TIMEOUT"},
            ],
            pending,
            False,
        ) == "TIMEOUT"

        try:
            load_journal_state(journal, {"n": "18", "curve_coefficients": problem["curve_coefficients"]})
        except DiscoveryError:
            pass
        else:
            raise AssertionError("journal identity mutation was accepted")

    return {
        "ok": True,
        "status": "PASSED",
        "tests": 10,
        "warning": "research-driver mechanics only; no theorem result",
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
