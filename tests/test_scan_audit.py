"""
Tests for scan_audit.audit_scan_results() — the offline scan-result audit.

All inputs are synthetic dicts shaped like scanner.py check outputs.
No network, no credentials, no real sites.

Run with:
    cd security-scanner
    python -m pytest tests/test_scan_audit.py -v
"""
import copy
import json

from scanner import compute_score, STRICTNESS_PROFILES, DEFAULT_STRICTNESS
from scan_audit import audit_scan_results


def _fail(category: str, severity: str, check_id: str = None) -> dict:
    r = {"category": category, "severity": severity, "passed": False}
    if check_id is not None:
        r["id"] = check_id
    return r


def _info_pass(category: str = "Headers", check_id: str = None) -> dict:
    r = {"category": category, "severity": "INFO", "passed": True}
    if check_id is not None:
        r["id"] = check_id
    return r


# ----------------------------------------------------------------------
# a) Normal path — mixed severities, excluded category, INFO passes.
#    Audit must match compute_score item-for-item.
# ----------------------------------------------------------------------

def _mixed_fixture() -> list:
    return [
        _fail("Headers", "CRITICAL", "h-crit"),
        _fail("Headers", "HIGH", "h-high-1"),
        _fail("Cookies", "HIGH", "c-high"),
        _fail("DNS", "MEDIUM", "d-med"),
        _fail("Redirect", "LOW", "r-low"),
        _fail("SEO", "HIGH", "seo-high"),          # excluded in standard
        _fail("GDPR", "MEDIUM", "gdpr-med"),       # excluded in standard
        _info_pass("Headers", "info-1"),
        _info_pass("Extras", "info-2"),
        {"category": "CMS", "severity": "INFO", "passed": True, "id": "info-3"},
    ]


def test_normal_path_matches_compute_score_standard():
    results = _mixed_fixture()
    audit = audit_scan_results(results, strictness="standard")
    ref = compute_score(results, strictness="standard")

    assert audit["score"] == ref["score"]
    assert audit["grade"] == ref["grade"]
    assert audit["consistent_with_compute_score"] is True

    # Hand-computed expectations for the standard profile:
    # deduction = 1*20 + min(2,4)*10 + 1*5 + 1*2 = 47
    assert audit["deduction"]["total"] == 47
    assert audit["deduction_total"] == 47
    # bonus = min(3 * 2, 20) = 4
    assert audit["bonus"]["info_passed"] == 3
    assert audit["bonus"]["raw"] == 6
    assert audit["bonus"]["applied"] == 6
    assert audit["bonus_applied"] == 6
    # score = 100 - 47 + 6 = 59 -> grade D (thresholds A=90..D=40)
    assert audit["score"] == 59
    assert audit["grade"] == "D"

    # Excluded categories: SEO + GDPR entries dropped before scoring
    assert audit["excluded"]["count"] == 2
    assert audit["excluded"]["categories"] == ["GDPR", "SEO"]

    # Bucket detail
    b = audit["deduction"]["buckets"]
    assert b["CRITICAL"] == {"failed": 1, "counted": 1, "capped": False,
                             "weight": 20, "subtotal": 20}
    assert b["HIGH"]["failed"] == 2 and b["HIGH"]["counted"] == 2
    assert b["MEDIUM"]["subtotal"] == 5
    assert b["LOW"]["subtotal"] == 2

    assert audit["inconsistencies"] == []


def test_normal_path_matches_compute_score_every_profile():
    results = _mixed_fixture()
    for name in STRICTNESS_PROFILES:
        audit = audit_scan_results(results, strictness=name)
        ref = compute_score(results, strictness=name)
        assert audit["score"] == ref["score"], name
        assert audit["grade"] == ref["grade"], name
        assert audit["consistent_with_compute_score"] is True, name
        assert audit["strictness_effective"] == name
        assert audit["strictness_fallback"] is False


def test_report_is_json_serializable():
    audit = audit_scan_results(_mixed_fixture(), strictness="standard")
    json.dumps(audit)  # must not raise


def test_audit_does_not_mutate_results():
    results = _mixed_fixture()
    snapshot = copy.deepcopy(results)
    audit_scan_results(results, strictness="standard")
    assert results == snapshot


# ----------------------------------------------------------------------
# b) Negative path — passed=True with non-INFO severity is recorded,
#    and the audit never raises on malformed entries.
# ----------------------------------------------------------------------

def test_passed_true_with_high_severity_recorded_not_raised():
    results = [
        {"id": "weird-1", "category": "Headers", "severity": "HIGH",
         "passed": True},
        _fail("Headers", "MEDIUM", "ok-fail"),
    ]
    audit = audit_scan_results(results, strictness="standard")

    flagged = [i for i in audit["inconsistencies"] if i["id"] == "weird-1"]
    assert len(flagged) == 1
    assert "passed=True" in flagged[0]["reason"]
    assert "HIGH" in flagged[0]["reason"]

    # Audit still recomputes consistently despite the odd entry
    ref = compute_score(results, strictness="standard")
    assert audit["score"] == ref["score"]
    assert audit["grade"] == ref["grade"]


def test_unknown_severity_and_missing_severity_recorded():
    results = [
        {"id": "bad-sev", "category": "Headers", "severity": "BOGUS",
         "passed": False},
        {"id": "no-sev", "category": "DNS", "passed": False},
    ]
    audit = audit_scan_results(results, strictness="standard")

    by_id = {i["id"]: i for i in audit["inconsistencies"]}
    assert "bad-sev" in by_id and "BOGUS" in by_id["bad-sev"]["reason"]
    assert "no-sev" in by_id and "severity" in by_id["no-sev"]["reason"]

    # compute_score treats missing severity as LOW; unknown severity is
    # ignored by bucketing — audit must reproduce that exactly.
    ref = compute_score(results, strictness="standard")
    assert audit["score"] == ref["score"]
    assert audit["deduction"]["buckets"]["LOW"]["failed"] == 1


# ----------------------------------------------------------------------
# c) Boundary — empty results: score 100, every bucket empty.
# ----------------------------------------------------------------------

def test_empty_results_scores_100_with_zero_buckets():
    audit = audit_scan_results([], strictness="standard")

    assert audit["score"] == 100
    assert audit["grade"] == "A"
    assert audit["total_results"] == 0
    assert audit["excluded"]["count"] == 0
    assert audit["excluded"]["categories"] == []
    assert audit["deduction"]["total"] == 0
    assert audit["bonus"]["info_passed"] == 0
    assert audit["bonus"]["applied"] == 0
    assert audit["inconsistencies"] == []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bucket = audit["deduction"]["buckets"][sev]
        assert bucket["failed"] == 0
        assert bucket["counted"] == 0
        assert bucket["subtotal"] == 0

    ref = compute_score([], strictness="standard")
    assert audit["score"] == ref["score"]
    assert audit["grade"] == ref["grade"]


# ----------------------------------------------------------------------
# d) Diminishing caps — counted entries equal the cap, not the total.
# ----------------------------------------------------------------------

def test_diminishing_cap_limits_counted_entries():
    # standard caps HIGH at 4; 7 HIGH failures -> counted == 4
    results = [_fail("Headers", "HIGH", f"h{i}") for i in range(7)]
    audit = audit_scan_results(results, strictness="standard")

    bucket = audit["deduction"]["buckets"]["HIGH"]
    assert bucket["failed"] == 7
    assert bucket["counted"] == 4   # cap, not the raw total
    assert bucket["capped"] is True
    assert bucket["subtotal"] == 4 * 10
    assert audit["deduction"]["total"] == 40

    ref = compute_score(results, strictness="standard")
    assert audit["score"] == ref["score"] == 60
    assert audit["grade"] == ref["grade"]


def test_no_diminishing_profile_counts_everything():
    # strict has diminishing=False -> all 7 HIGH count (weight 15)
    results = [_fail("Headers", "HIGH") for _ in range(7)]
    audit = audit_scan_results(results, strictness="strict")

    bucket = audit["deduction"]["buckets"]["HIGH"]
    assert bucket["failed"] == 7
    assert bucket["counted"] == 7
    assert bucket["capped"] is False
    assert bucket["subtotal"] == 105
    ref = compute_score(results, strictness="strict")
    assert audit["score"] == ref["score"] == 5  # floor


def test_bonus_cap_limits_applied_bonus():
    # standard: bonus_per_info=2, bonus_cap=20 -> 15 INFO passes
    # give raw 30 but applied 20.
    results = [_info_pass() for _ in range(15)]
    audit = audit_scan_results(results, strictness="standard")
    assert audit["bonus"]["info_passed"] == 15
    assert audit["bonus"]["raw"] == 30
    assert audit["bonus"]["applied"] == 20


# ----------------------------------------------------------------------
# e) Unknown strictness — falls back to DEFAULT_STRICTNESS, report says so.
# ----------------------------------------------------------------------

def test_unknown_strictness_falls_back_and_is_labelled():
    results = _mixed_fixture()
    audit = audit_scan_results(results, strictness="definitely-not-a-profile")
    ref = compute_score(results, strictness="definitely-not-a-profile")

    assert audit["strictness_requested"] == "definitely-not-a-profile"
    assert audit["strictness_effective"] == DEFAULT_STRICTNESS == "standard"
    assert audit["strictness_fallback"] is True
    assert audit["score"] == ref["score"]
    assert audit["grade"] == ref["grade"]
    assert audit["consistent_with_compute_score"] is True

    # And it must equal an explicit standard run, like compute_score does.
    audit_std = audit_scan_results(results, strictness="standard")
    assert audit["score"] == audit_std["score"]
    assert audit["grade"] == audit_std["grade"]
    assert audit["deduction"]["total"] == audit_std["deduction"]["total"]
    assert audit["bonus"]["applied"] == audit_std["bonus"]["applied"]


def test_none_strictness_uses_default():
    audit = audit_scan_results([], strictness=None)
    assert audit["strictness_effective"] == DEFAULT_STRICTNESS
    assert audit["score"] == 100
