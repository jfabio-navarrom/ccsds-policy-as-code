#!/usr/bin/env python3
"""End-to-end check with Conftest on the example SA databases.

* Every file in examples/compliant/ must produce zero failures and warnings.
* Every file in examples/non-compliant/ must produce exactly the policy IDs
  listed in examples/non-compliant/expected.json: no misses (a regression
  that stops catching a known-bad config) and no extras (a false positive).
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFTEST = "conftest"


def run(path):
    proc = subprocess.run(
        [CONFTEST, "test", str(path), "-p", str(ROOT / "policy"), "--all-namespaces", "-o", "json"],
        capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):
        sys.exit(f"conftest error on {path}:\n{proc.stderr}")
    fails, warns = set(), set()
    for result in json.loads(proc.stdout):
        fails |= {f["metadata"]["policy_id"] for f in result.get("failures") or []}
        warns |= {w["metadata"]["policy_id"] for w in result.get("warnings") or []}
    return fails, warns


def main():
    ok = True
    for f in sorted((ROOT / "examples" / "compliant").glob("*.yaml")):
        fails, warns = run(f)
        status = "ok" if not fails and not warns else "FAIL"
        ok &= status == "ok"
        print(f"[{status}] {f.name}: expected clean, got failures={sorted(fails)} warnings={sorted(warns)}")

    expected = json.loads((ROOT / "examples" / "non-compliant" / "expected.json").read_text())
    for name, exp in expected.items():
        fails, warns = run(ROOT / "examples" / "non-compliant" / name)
        problems = []
        if fails != set(exp["failures"]):
            problems.append(f"failures missing={sorted(set(exp['failures']) - fails)} extra={sorted(fails - set(exp['failures']))}")
        if warns != set(exp["warnings"]):
            problems.append(f"warnings missing={sorted(set(exp['warnings']) - warns)} extra={sorted(warns - set(exp['warnings']))}")
        ok &= not problems
        print(f"[{'FAIL' if problems else 'ok'}] {name}: {'; '.join(problems) or f'{len(fails)} failures, {len(warns)} warnings as expected'}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
