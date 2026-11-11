# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Offline scan-result audit.

Pure, read-only re-computation of the scoring pipeline in
``scanner.compute_score()``. Given the ``results`` list produced by a scan
and a ``strictness`` string, ``audit_scan_results()`` returns a structured,
JSON-serializable report that explains exactly how the score was derived:

  1. which results were excluded by the profile's ``excluded_categories``;
  2. how the remaining failures bucket by severity, how many entries per
     bucket actually count toward the penalty (diminishing caps), and each
     bucket's deduction subtotal;
  3. the INFO-pass bonus, raw vs. capped;
  4. the recomputed deduction / bonus / score / grade, cross-checked
     against ``scanner.compute_score()`` on the same input;
  5. data-quality inconsistencies (unknown severity, passed=True with a
     non-INFO severity, missing severity field).

The audit NEVER mutates the input list or its items, never changes
``STRICTNESS_PROFILES`` or the scoring formula, and performs no I/O —
it runs fully offline. Profile values are read from ``scanner`` at call
time (deferred import to avoid a circular import, since ``scanner``
imports this module to attach the audit to its return value), so the
audit can never drift from the scoring it audits.
"""
from typing import Any, Dict, List, Optional

# Severity ladder recognised by the scoring pipeline. Anything outside
# this set is an inconsistency; only the first four carry penalties.
SEVERITY_LADDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_PENALIZED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _scanner():
    """Deferred import of scanner (it imports this module at top level)."""
    import scanner
    return scanner


def _resolve_profile(strictness: Optional[str]):
    """Mirror compute_score's fallback: unknown -> DEFAULT_STRICTNESS."""
    scanner = _scanner()
    profiles = scanner.STRICTNESS_PROFILES
    default = scanner.DEFAULT_STRICTNESS
    requested = default if strictness is None else strictness
    if requested in profiles:
        return scanner, profiles[requested], requested, requested, False
    return scanner, profiles[default], requested, default, True


def audit_scan_results(
    results: List[Dict[str, Any]],
    strictness: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Audit one scan's results against a strictness profile.

    Args:
        results: List of check-result dicts as produced by scanner.scan()
            (keys used: category, severity, passed, id). Read-only.
        strictness: Profile name. Unknown values (and None) fall back to
            scanner.DEFAULT_STRICTNESS, exactly like compute_score().

    Returns:
        A JSON-serializable dict (pure data — no sets, no custom objects).
    """
    scanner, profile, requested, effective, fell_back = _resolve_profile(strictness)

    weights = profile["weights"]
    excluded = set(profile["excluded_categories"])
    diminishing = bool(profile["diminishing"])
    caps = profile["diminishing_caps"]

    # Shallow copy of the list so even incidental list-level mutation is
    # impossible; item dicts are only ever read.
    items: List[Dict[str, Any]] = list(results)

    # --- 5) Data-quality inconsistencies --------------------------------
    inconsistencies: List[Dict[str, Any]] = []
    for i, item in enumerate(items):
        item_id = item.get("id")
        if "severity" not in item:
            inconsistencies.append({
                "index": i,
                "id": item_id,
                "reason": "missing 'severity' field; scoring treats a "
                          "failed entry without severity as LOW",
            })
        elif item["severity"] not in SEVERITY_LADDER:
            inconsistencies.append({
                "index": i,
                "id": item_id,
                "reason": f"severity {item['severity']!r} is not in the "
                          f"CRITICAL/HIGH/MEDIUM/LOW/INFO ladder; it is "
                          f"ignored by penalty bucketing",
            })
        if item.get("passed") and item.get("severity") != "INFO":
            inconsistencies.append({
                "index": i,
                "id": item_id,
                "reason": "passed=True but severity is "
                          f"{item.get('severity')!r} (only INFO passes earn "
                          f"bonus; a passed non-INFO entry neither helps "
                          f"nor hurts the score)",
            })

    # --- 1) Excluded categories ------------------------------------------
    excluded_items = [r for r in items if r.get("category") in excluded]
    excluded_report = {
        "count": len(excluded_items),
        "categories": sorted({r.get("category") for r in excluded_items}),
        "configured_categories": sorted(excluded),
    }

    # --- 2) Failure buckets (mirrors compute_score exactly) --------------
    security_results = [r for r in items if r.get("category") not in excluded]
    failed = [r for r in security_results if not r.get("passed", True)]

    by_sev: Dict[str, List[Dict[str, Any]]] = {s: [] for s in _PENALIZED_SEVERITIES}
    for item in failed:
        sev = item.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev].append(item)

    buckets: Dict[str, Dict[str, Any]] = {}
    deduction = 0.0
    for sev in _PENALIZED_SEVERITIES:
        total = len(by_sev[sev])
        counted = min(total, caps[sev]) if diminishing else total
        subtotal = counted * weights[sev]
        deduction += subtotal
        buckets[sev] = {
            "failed": total,            # all failed entries in this bucket
            "counted": counted,         # entries actually penalized (cap)
            "capped": bool(diminishing and total > counted),
            "weight": weights[sev],
            "subtotal": subtotal,
        }

    # --- 3) INFO-pass bonus ----------------------------------------------
    info_passed = [r for r in items
                   if r.get("passed", False) and r.get("severity") == "INFO"]
    raw_bonus = len(info_passed) * profile["bonus_per_info"]
    bonus = min(raw_bonus, profile["bonus_cap"])

    # --- 4) Recomputed score / grade -------------------------------------
    score = max(5, min(100, 100 - deduction + bonus))
    score = round(score)

    thresholds = profile["grade_thresholds"]
    if score >= thresholds["A"]:
        grade = "A"
    elif score >= thresholds["B"]:
        grade = "B"
    elif score >= thresholds["C"]:
        grade = "C"
    elif score >= thresholds["D"]:
        grade = "D"
    else:
        grade = "F"

    # Cross-check against the reference implementation on the same input.
    reference = scanner.compute_score(results, strictness=strictness)
    consistent = (score == reference["score"] and grade == reference["grade"])

    return {
        "strictness_requested": requested,
        "strictness_effective": effective,
        "strictness_fallback": fell_back,
        "total_results": len(items),
        "excluded": excluded_report,
        "deduction": {
            "diminishing": diminishing,
            "buckets": buckets,
            "total": deduction,
        },
        "bonus": {
            "info_passed": len(info_passed),
            "per_info": profile["bonus_per_info"],
            "raw": raw_bonus,
            "cap": profile["bonus_cap"],
            "applied": bonus,
        },
        "deduction_total": deduction,
        "bonus_applied": bonus,
        "score": score,
        "grade": grade,
        "consistent_with_compute_score": consistent,
        "inconsistencies": inconsistencies,
    }
