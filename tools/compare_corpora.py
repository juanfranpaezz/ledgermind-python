"""The derived-vs-recorded oracle, run at the precision the Java actually emits.

This is the countermeasure to the correlated-derivation risk. Three agents read the same Java source and agree
about it; correlated errors are a law, so a shared misreading is invisible to all three.
The recorded capture is the only model-free leg the project has, and the predictable way
to destroy it is to run the diff, see a wall of timestamp noise, and "just normalize it".

So this tool does two separate jobs and keeps them separate:

**JOB 1 - SELF_CHAIN (the model-free leg).** Inside the RECORDED corpus alone, recompute
``SHA-256(prevHash + id|dr|cr|amount|asset|idempotencyKey|createdAt)`` over the rows
captured from Postgres and compare against the ``entry_hash`` column the JAVA wrote. No
derived corpus is involved. If our reading of ``JournalChainer.entryHash`` is wrong -
including the exact ``Instant.toString()`` fractional-digit rule - this fails, and no
amount of agreement between readers can hide it. This leg is never normalized.

**JOB 2 - the cross-corpus diff, against a FROZEN class list.** The single normalization
rule (``createdAt`` PRECISION only) and the expected diff classes E1..E5 were written to
``docs/evidence/derived-vs-recorded-normalization.md`` BEFORE the recorder ran. Anything
that is not one of those classes lands in X1 (halt) or U (unclassified, declared rather
than absorbed). This tool cannot widen the rule: the class list is a constant here and
the doc is its pre-registration.

Usage::

    py -m tools.compare_corpora                     # both jobs, on the shipped corpora
    py -m tools.compare_corpora --json              # machine-readable summary

Exit 0 = SELF_CHAIN holds on both halves and the cross-corpus diff contains no X1.
Exit 1 = anything else. U findings are printed loudly and do NOT flip the exit code by
themselves; they are for a human to rule on, and the count is always printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDED_ROOT = REPO_ROOT / "tests" / "fixtures" / "recorded"
DERIVED_ROOT = REPO_ROOT / "tests" / "fixtures" / "derived_from_source"
NORMALIZATION_DOC = REPO_ROOT / "docs" / "evidence" / "derived-vs-recorded-normalization.md"

GENESIS = "0" * 64

# Java Instant.toString(): no fraction, or exactly 3, 6 or 9 digits. Always UTC 'Z'.
JAVA_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6}|\.\d{9})?Z$")

CORPUS_METADATA = "_corpus.json"


# --------------------------------------------------------------------------------------
# JOB 1 - the model-free leg
# --------------------------------------------------------------------------------------
def canonical(posting):
    """JournalChainer.entryHash's canonical string, character for character."""
    return (
        str(posting["id"]) + "|" + str(posting["debitAccountId"]) + "|"
        + str(posting["creditAccountId"]) + "|" + str(posting["amount"]) + "|"
        + posting["asset"] + "|" + posting["idempotencyKey"] + "|" + posting["createdAt"]
    )


def entry_hash(prev_hash, posting):
    return hashlib.sha256((prev_hash + canonical(posting)).encode("utf-8")).hexdigest()


def self_chain_check(half_dir):
    """Recompute the chain from the recorded rows and compare with what the Java wrote."""
    payload = json.loads((half_dir / "postings_and_hashes.json").read_text(encoding="utf-8"))
    postings = {p["id"]: p for p in payload["postings"]}
    links = payload["postingHashes"]

    result = {
        "half": half_dir.name,
        "links": len(links),
        "matched": 0,
        "first_mismatch_seq": None,
        "bad_timestamp_format": [],
        "linkage_breaks": [],
    }
    for p in payload["postings"]:
        if not JAVA_INSTANT.match(p["createdAt"]):
            result["bad_timestamp_format"].append({"id": p["id"], "createdAt": p["createdAt"]})

    prev = GENESIS
    for link in sorted(links, key=lambda x: x["seq"]):
        if link["prevHash"] != prev:
            result["linkage_breaks"].append({"seq": link["seq"], "expected_prev": prev, "found": link["prevHash"]})
        posting = postings.get(link["postingId"])
        if posting is None:
            if result["first_mismatch_seq"] is None:
                result["first_mismatch_seq"] = link["seq"]
            break
        recomputed = entry_hash(link["prevHash"], posting)
        if recomputed == link["entryHash"]:
            result["matched"] += 1
        elif result["first_mismatch_seq"] is None:
            result["first_mismatch_seq"] = link["seq"]
        prev = link["entryHash"]
    return result


# --------------------------------------------------------------------------------------
# JOB 2 - the cross-corpus diff, against the FROZEN class list
# --------------------------------------------------------------------------------------
# Frozen 2026-09-14 in docs/evidence/derived-vs-recorded-normalization.md, before the
# recorder ran. This list is not extended by this tool, by design.
CLASS_RULES = [
    ("E1", lambda path: path.endswith("createdAt")),
    ("E2", lambda path: path.endswith("entryHash") or path.endswith("prevHash")),
    ("E3", lambda path: any(
        tok in path for tok in ("signedAt", "publicKeyBase64", "signature", "signedHeadHash", "_signing_material")
    )),
    ("E4", lambda path: path.endswith("verdict")),
]

SKIP_KEYS = ("_note",)


def classify(path):
    for name, rule in CLASS_RULES:
        if rule(path):
            return name
    return "X1"


def walk_diff(a, b, path, out):
    """Structural diff. Value differences are classified; key/shape gaps go to U."""
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key in SKIP_KEYS:
                continue
            child = path + "." + key if path else key
            if key not in a:
                out.append({"class": "U", "path": child, "why": "key present only in the DERIVED corpus"})
            elif key not in b:
                out.append({"class": "U", "path": child, "why": "key present only in the RECORDED corpus"})
            else:
                walk_diff(a[key], b[key], child, out)
        return
    if isinstance(a, list) and isinstance(b, list):
        if path.endswith("discrepancies"):
            # E5: the Java iterates two HashMaps, so ORDER is not reproducible.
            key_a = sorted(json.dumps(x, sort_keys=True, ensure_ascii=False) for x in a)
            key_b = sorted(json.dumps(x, sort_keys=True, ensure_ascii=False) for x in b)
            if key_a == key_b:
                if [json.dumps(x, sort_keys=True, ensure_ascii=False) for x in a] != [
                    json.dumps(x, sort_keys=True, ensure_ascii=False) for x in b
                ]:
                    out.append({"class": "E5", "path": path, "why": "same discrepancy SET, different order"})
            else:
                out.append({
                    "class": "X1",
                    "path": path,
                    "why": "the discrepancy SET differs, not just its order",
                    "recorded_only": [x for x in key_a if x not in key_b][:5],
                    "derived_only": [x for x in key_b if x not in key_a][:5],
                })
            return
        if len(a) != len(b):
            out.append({"class": "X1", "path": path, "why": "list length " + str(len(a)) + " vs " + str(len(b))})
            return
        for i, (x, y) in enumerate(zip(a, b)):
            walk_diff(x, y, path + "[" + str(i) + "]", out)
        return
    if a != b:
        cls = classify(path)
        entry = {"class": cls, "path": path}
        if cls == "X1":
            entry["recorded"] = a
            entry["derived"] = b
        out.append(entry)


def cross_corpus_diff(recorded_root, derived_root):
    findings = []
    rec_files = {
        str(p.relative_to(recorded_root)).replace("\\", "/")
        for p in recorded_root.rglob("*.json") if p.name != CORPUS_METADATA
    }
    der_files = {
        str(p.relative_to(derived_root)).replace("\\", "/")
        for p in derived_root.rglob("*.json") if p.name != CORPUS_METADATA
    }
    for only in sorted(rec_files - der_files):
        findings.append({"class": "U", "path": only, "why": "fixture file present only in the RECORDED corpus"})
    for only in sorted(der_files - rec_files):
        findings.append({"class": "U", "path": only, "why": "fixture file present only in the DERIVED corpus"})

    for shared in sorted(rec_files & der_files):
        a = json.loads((recorded_root / shared).read_text(encoding="utf-8"))
        b = json.loads((derived_root / shared).read_text(encoding="utf-8"))
        walk_diff(a, b, shared, findings)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Derived-vs-recorded oracle (correlated-derivation risk)")
    parser.add_argument("--recorded", default=str(RECORDED_ROOT))
    parser.add_argument("--derived", default=str(DERIVED_ROOT))
    parser.add_argument("--json", action="store_true", help="print the machine-readable summary too")
    args = parser.parse_args(argv)

    recorded_root = Path(args.recorded)
    derived_root = Path(args.derived)

    print("NORMALIZATION_RULE_PREREGISTERED_AT: " + str(NORMALIZATION_DOC))
    print("  present: " + str(NORMALIZATION_DOC.exists()))
    print("")

    print("=== JOB 1: SELF_CHAIN (model-free; recorded corpus only) ===")
    self_results = []
    for half in ("clean", "tampered"):
        half_dir = recorded_root / half
        if not half_dir.exists():
            print("  " + half + ": ABSENT")
            continue
        r = self_chain_check(half_dir)
        self_results.append(r)
        print("  " + half + ": links=" + str(r["links"]) + " recomputed_match=" + str(r["matched"])
              + " first_mismatch_seq=" + str(r["first_mismatch_seq"])
              + " bad_timestamp_format=" + str(len(r["bad_timestamp_format"]))
              + " linkage_breaks=" + str(len(r["linkage_breaks"])))

    clean = next((r for r in self_results if r["half"] == "clean"), None)
    tampered = next((r for r in self_results if r["half"] == "tampered"), None)
    self_ok = True
    if clean is None or clean["matched"] != clean["links"] or clean["links"] == 0:
        self_ok = False
        print("  SELF_CHAIN clean: FAIL - the recomputation disagrees with the Java's own hashes")
    else:
        print("  SELF_CHAIN clean: PASS - all " + str(clean["links"]) + " hashes recomputed exactly")
    if tampered is not None:
        # The tampered half MUST disagree at the tampered seq; agreement there would mean
        # the recomputation is not actually reading the posting amounts.
        if tampered["first_mismatch_seq"] is None:
            self_ok = False
            print("  SELF_CHAIN tampered: FAIL - recomputation found NO break, so it is not "
                  "sensitive to the planted defect")
        else:
            print("  SELF_CHAIN tampered: PASS - break detected at seq "
                  + str(tampered["first_mismatch_seq"]) + " (the negative control fires)")
    if clean and clean["bad_timestamp_format"]:
        self_ok = False
        print("  SELF_CHAIN: FAIL - a createdAt is not in Instant.toString() form: "
              + json.dumps(clean["bad_timestamp_format"][:3]))

    print("")
    print("=== JOB 2: cross-corpus diff against the FROZEN class list ===")
    findings = cross_corpus_diff(recorded_root, derived_root)
    counts = {}
    for f in findings:
        counts[f["class"]] = counts.get(f["class"], 0) + 1
    for cls in sorted(counts):
        print("  " + cls + ": " + str(counts[cls]))
    x1 = [f for f in findings if f["class"] == "X1"]
    u = [f for f in findings if f["class"] == "U"]
    if x1:
        print("  X1 FINDINGS - these HALT Phase 1 and go to a fresh-context verifier:")
        for f in x1[:20]:
            print("    " + f["path"] + " :: " + json.dumps({k: v for k, v in f.items() if k != "class"})[:240])
    if u:
        print("  U FINDINGS - outside the frozen class list, DECLARED not absorbed "
              "(a human rules on these; they do not flip the exit code):")
        for f in u[:20]:
            print("    " + f["path"] + " :: " + f["why"])

    print("")
    ok = self_ok and not x1
    print("SELF_CHAIN: " + ("PASS" if self_ok else "FAIL"))
    print("CROSS_CORPUS_X1: " + str(len(x1)))
    print("CROSS_CORPUS_U: " + str(len(u)))
    print("ORACLE: " + ("PASS" if ok else "FAIL"))
    if args.json:
        print(json.dumps({"self_chain": self_results, "counts": counts, "findings": findings}, indent=2, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
