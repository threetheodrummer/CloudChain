"""
Weight sensitivity: how much do the hand-chosen weights drive the output?

Every multiplier in the finding score and every weight in the posture model is
scaled one at a time by 0.5x, 0.75x, 1.25x and 1.5x. For each perturbation we
measure, across 10 seeded synthetic organisations plus the demo organisation:

  - Kendall's tau-b between the baseline and perturbed finding scores
    (1.0 = identical ordering)
  - overlap of the top-10 findings (fraction of the baseline top 10 kept)
  - mean absolute change in the 0-100 posture score
  - fraction of organisations whose letter grade changes

Run from backend/:  python ../experiments/sensitivity.py
Writes experiments/results/sensitivity.csv.
"""
import copy, csv, os, statistics, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, os.path.dirname(__file__))

from scipy.stats import kendalltau  # noqa: E402

import app.risk.posture as posture  # noqa: E402
import app.risk.scoring as scoring  # noqa: E402
from app.models import Severity  # noqa: E402
from app.pipeline import analyse_sources  # noqa: E402
from app.report.generator import build_report  # noqa: E402
from app.sources import get_data_sources  # noqa: E402
from app.storage.drift import compare_scans  # noqa: E402
from synthetic_org import make_org  # noqa: E402

FACTORS = [0.5, 0.75, 1.25, 1.5]

# (label, getter, setter) for every tunable
def _attr(mod, name):
    return (lambda: getattr(mod, name), lambda v: setattr(mod, name, v))

def _key(d, k):
    return (lambda: d[k], lambda v: d.__setitem__(k, v))

PARAMS = [
    ("finding: internet-facing multiplier", *_attr(scoring, "INTERNET_FACING_MULTIPLIER")),
    ("finding: sensitive multiplier", *_attr(scoring, "SENSITIVE_MULTIPLIER")),
    ("finding: attack-path multiplier", *_attr(scoring, "ATTACK_PATH_MULTIPLIER")),
    ("finding: CRITICAL base weight", *_key(scoring.BASE_SEVERITY_WEIGHTS, Severity.CRITICAL)),
    ("finding: HIGH base weight", *_key(scoring.BASE_SEVERITY_WEIGHTS, Severity.HIGH)),
    ("posture: exposure weight", *_key(posture.COMPONENT_WEIGHTS, "exposure")),
    ("posture: privilege weight", *_key(posture.COMPONENT_WEIGHTS, "privilege")),
    ("posture: reachability weight", *_key(posture.COMPONENT_WEIGHTS, "reachability")),
    ("posture: blast-radius weight", *_key(posture.COMPONENT_WEIGHTS, "blast_radius")),
    ("posture: internet-path floor", *_attr(posture, "REACHABILITY_PATH_EXISTS")),
    ("posture: escalation-only floor", *_attr(posture, "REACHABILITY_ESCALATION_ONLY")),
    ("posture: exposure saturation", *_attr(posture, "EXPOSURE_SATURATION")),
    ("posture: privilege saturation", *_attr(posture, "PRIVILEGE_SATURATION")),
]


def orgs():
    out = [("demo", get_data_sources("demo"))]
    out += [(f"synthetic-{s}", make_org(300, 3, seed=s)) for s in range(10)]
    return out


def evaluate(results):
    """Finding scores and posture for every org under the current weights."""
    out = {}
    for name, result in results:
        scores = [scoring.score_finding(f, f.in_attack_path) for f in result.findings]
        p = build_report(result, compare_scans(result, None))["posture"]
        out[name] = (scores, p["score"], p["grade"])
    return out


def top10(scores):
    order = sorted(range(len(scores)), key=lambda i: (-scores[i], i))
    return set(order[:10])


def main():
    results = [(n, analyse_sources(src, scan_id=n, mode="real")) for n, src in orgs()]
    base = evaluate(results)
    rows = []
    for label, get, set_ in PARAMS:
        original = get()
        for f in FACTORS:
            set_(original * f)
            try:
                pert = evaluate(results)
            finally:
                set_(original)
            taus, overlaps, deltas, grade_changes = [], [], [], 0
            for name in base:
                b_scores, b_post, b_grade = base[name]
                p_scores, p_post, p_grade = pert[name]
                if len(set(b_scores)) > 1:
                    taus.append(kendalltau(b_scores, p_scores).statistic)
                overlaps.append(len(top10(b_scores) & top10(p_scores)) / max(1, min(10, len(b_scores))))
                deltas.append(abs(p_post - b_post))
                grade_changes += b_grade != p_grade
            row = {
                "parameter": label, "factor": f,
                "kendall_tau_min": round(min(taus), 3), "kendall_tau_mean": round(statistics.mean(taus), 3),
                "top10_overlap_mean": round(statistics.mean(overlaps), 3),
                "posture_abs_change_mean": round(statistics.mean(deltas), 2),
                "posture_abs_change_max": round(max(deltas), 2),
                "grade_changed_fraction": round(grade_changes / len(base), 3),
            }
            rows.append(row)
            print(row, flush=True)
    out = os.path.join(os.path.dirname(__file__), "results", "sensitivity.csv")
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


if __name__ == "__main__":
    main()
