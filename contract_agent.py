#!/usr/bin/env python3
"""
Contract Driven Agent - SDD/TDD/BDD workflow for Black Sand Beacon v2.
Reads CLAUDE.md contracts and executes the full workflow.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path("/home/grisun0/src_note/c/blacksandbeacon")
SPEC_DIR = REPO_ROOT / "spec"
TEST_DIR = REPO_ROOT / "tests"
SRC_DIR = REPO_ROOT / "src"
INCLUDE_DIR = REPO_ROOT / "include"
MAKEFILE = REPO_ROOT / "Makefile"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


def run_cmd(cmd: List[str], cwd: Path = REPO_ROOT) -> Tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr)."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    return result.returncode, result.stdout, result.stderr


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def git(*args):
    return run_cmd(["git"] + list(args))


def make_target(target: str):
    return run_cmd(["make", target])


def extract_contracts(claude_content: str) -> List[Tuple[str, str]]:
    """Extract contracts from CLAUDE.md (## Contract: Name headings)."""
    contracts = []
    lines = claude_content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("## Contract: "):
            name = line[13:].strip()
            body_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("## "):
                body_lines.append(lines[i])
                i += 1
            body = "\n".join(body_lines).strip()
            contracts.append((name, body))
            continue
        i += 1
    return contracts


def write_spec(contract_name: str, body: str):
    """Write spec/<contract_name>.md with SDD template."""
    safe_name = contract_name.lower().replace(" ", "_").replace("/", "_")
    spec_path = SPEC_DIR / f"{safe_name}.md"
    ensure_dir(SPEC_DIR)
    content = f"""# {contract_name} Specification

## Purpose
{body}

## Inputs
- TBD

## Outputs
- TBD

## Error Conditions
- TBD

## Security Guarantees
- Zero Trust: no implicit trust between components.
- Zero Knowledge: minimal data retention.
- Privacy by Default: no telemetry.
- Secure by Default: fail-closed.
- Post-Quantum by Default: TLS 1.3 with hybrid KEM.
- Agent-Safe: deterministic, structured output.

## Open Issues
- None
"""
    spec_path.write_text(content)
    return spec_path


def write_python_test(contract_name: str, body: str):
    """Write a failing pytest test for the contract."""
    safe_name = contract_name.lower().replace(" ", "_").replace("/", "_")
    test_path = TEST_DIR / f"test_{safe_name}.py"
    ensure_dir(TEST_DIR)

    # Extract key requirements from body to generate meaningful test
    content = f'''"""
Auto-generated test for contract: {contract_name}
BDD-style tests derived from specification.
"""
import pytest
import json
import tempfile
import os
from pathlib import Path

# Add include to path for config loader
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "include"))

import sys


class Test{contract_name.replace(" ", "").replace("/", "")}:
    """BDD test suite for {contract_name}."""

    def test_placeholder_fails_initially(self):
        """This test should fail until implementation is complete."""
        # TODO: Replace with real assertions based on spec
        assert False, "Contract not yet implemented - replace this test"

    # TODO: Add BDD scenarios from spec
    # Example:
    # def test_given_valid_config_when_load_then_keys_derived(self):
    #     ...


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
'''
    test_path.write_text(content)
    return test_path


def write_c_test(contract_name: str, body: str):
    """Write a failing CMocka test for C components."""
    safe_name = contract_name.lower().replace(" ", "_").replace("/", "_")
    test_path = TEST_DIR / f"test_{safe_name}_c.c"
    ensure_dir(TEST_DIR)

    content = f'''/*
 * Auto-generated C test for contract: {contract_name}
 * Uses CMocka framework.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>

/* TODO: Include the header under test */
/* #include "beacon_common.h" */

static void test_{safe_name}_placeholder(void **state)
{{
    (void) state; /* unused */
    /* Placeholder - replace with real assertions */
    assert_true(false);
}}

int main(void)
{{
    const struct CMUnitTest tests[] = {{
        cmocka_unit_test(test_{safe_name}_placeholder),
    }};
    return cmocka_run_group_tests(tests, NULL, NULL);
}}
'''
    test_path.write_text(content)
    return test_path


def write_implementation_stub(contract_name: str):
    """Write minimal C implementation stub."""
    safe_name = contract_name.lower().replace(" ", "_").replace("/", "_")
    impl_path = SRC_DIR / f"{safe_name}.c"
    ensure_dir(SRC_DIR)

    content = f'''#include "{safe_name}.h"
/* Auto-generated implementation for contract: {contract_name} */
/* TODO: replace with real logic compliant with the spec */
#include <stdbool.h>

bool {safe_name}_process(void)
{{
    /* Minimal implementation to make the test pass */
    return true;
}}
'''

    # Ensure header exists
    header_path = INCLUDE_DIR / f"{safe_name}.h"
    if not header_path.exists():
        header_content = f'''#ifndef {safe_name.upper()}_H
#define {safe_name.upper()}_H

bool {safe_name}_process(void);

#endif /* {safe_name.upper()}_H */
'''
        header_path.write_text(header_content)

    impl_path.write_text(content)
    return impl_path


def run_python_tests() -> bool:
    """Run pytest and return True if all pass."""
    exit_code, out, err = make_target("test")
    if exit_code != 0:
        print("Python test output:\n", out)
        print("Python test errors:\n", err)
        return False
    return True


def run_c_tests() -> bool:
    """Run C tests via make test (assumes Makefile has C test targets)."""
    exit_code, out, err = run_cmd(["make", "test-c"])
    if exit_code != 0:
        print("C test output:\n", out)
        print("C test errors:\n", err)
        return False
    return True


def run_mutation_testing() -> bool:
    """Run mutation testing with mutmut (Python) and custom (C)."""
    print("\n=== Running Mutation Testing ===")

    # Python mutation testing with mutmut
    exit_code, out, err = run_cmd(["mutmut", "run", "--paths-to-mutate", "c2/", "tests/", "--runner", "python -m pytest"])
    print("mutmut output:", out)
    if exit_code != 0:
        print("mutmut errors:", err)

    # Get mutation score
    exit_code, out, err = run_cmd(["mutmut", "results"])
    print("Mutation results:", out)

    # C mutation testing - custom script
    exit_code, out, err = run_cmd([sys.executable, "scripts/mutation_test_c.py"])
    print("C mutation output:", out)
    if exit_code != 0:
        print("C mutation errors:", err)

    return True  # Don't fail the build on mutation score yet


def run_asan() -> bool:
    """Run AddressSanitizer build and tests."""
    exit_code, out, err = make_target("asan")
    if exit_code != 0:
        print("ASan output:\n", out)
        print("ASan errors:\n", err)
        return False
    return True


def run_qa() -> bool:
    """Run static analysis (cppcheck)."""
    exit_code, out, err = run_cmd(["cppcheck", "--enable=all", "--inconclusive", "--std=c11", "beacons/", "include/", "tests/*_harness.c"])
    if exit_code != 0:
        print("QA (cppcheck) issues found:\n", out)
        return False
    return True


def git_commit_and_branch(contract_name: str):
    """Create a new branch, add changes, commit."""
    safe_name = contract_name.lower().replace(" ", "_").replace("/", "_")
    branch_name = f"contract/{safe_name}"
    exit_code, _, _ = git("rev-parse", "--is-inside-work-tree")
    if exit_code != 0:
        print("Not a git repository")
        return False
    git("checkout", "-b", branch_name)
    git("add", "spec/", "tests/", "src/", "include/", "CLAUDE.md")
    git("commit", "-m", f"feat: add contract {contract_name} (SDD/TDD/BDD)")
    return True


def process_contract(contract_name: str, body: str):
    """Execute the full SDD+TDD+BDD workflow for a single contract."""
    print(f"\n=== Processing contract: {contract_name} ===")

    spec_path = write_spec(contract_name, body)
    print(f"Spec written to {spec_path}")

    # Write both Python and C tests
    py_test_path = write_python_test(contract_name, body)
    print(f"Python test written to {py_test_path}")

    c_test_path = write_c_test(contract_name, body)
    print(f"C test written to {c_test_path}")

    impl_path = write_implementation_stub(contract_name)
    print(f"Implementation stub written to {impl_path}")

    # TDD cycle: run tests, they should fail
    print("Running tests (expected to fail initially)...")
    run_python_tests()
    run_c_tests()

    print(f"=== Contract {contract_name} setup complete ===")
    print("Next: Implement the contract to make tests pass.")
    return True


def main():
    if not CLAUDE_MD.is_file():
        print(f"ERROR: {CLAUDE_MD} not found.")
        sys.exit(1)

    claude_content = CLAUDE_MD.read_text()
    contracts = extract_contracts(claude_content)

    if not contracts:
        print("No contracts found in CLAUDE.md (looking for '## Contract: ' headings).")
        sys.exit(0)

    print(f"Found {len(contracts)} contracts:")
    for name, _ in contracts:
        print(f"  - {name}")

    for name, body in contracts:
        success = process_contract(name, body)
        if not success:
            print(f"Halting due to failure in contract '{name}'.")
            sys.exit(1)

    print("\nAll contracts set up. Now implement each to make tests pass.")
    print("Run 'make test' to verify, then 'make mutation-test' for mutation testing.")


if __name__ == "__main__":
    main()