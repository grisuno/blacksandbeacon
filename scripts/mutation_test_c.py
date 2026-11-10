#!/usr/bin/env python3
"""
C Mutation Testing Script

This script performs mutation testing on C code by:
1. Creating mutated copies of source files
2. Compiling and running tests against each mutant
3. Reporting killed vs surviving mutants

Mutation operators:
- Arithmetic replacement (+ -> -, - -> +, * -> /, / -> *)
- Relational replacement (< -> >, > -> <, <= -> >=, >= -> <=, == -> !=, != -> ==)
- Logical replacement (&& -> ||, || -> &&, ! -> (removed))
- Constant replacement (0 -> 1, 1 -> 0, -1 -> 1, TRUE -> FALSE, FALSE -> TRUE)
- Statement deletion (remove entire statements)
- Return value replacement (return 0 -> return 1, etc.)
"""

import os
import re
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from typing import List, Tuple, Dict

ROOT = Path(__file__).resolve().parent.parent
SRC_DIRS = [
    ROOT / "include",
    ROOT / "beacons" / "v1",
]
TEST_DIR = ROOT / "tests"
BUILD_DIR = ROOT / "build"

# Mutation operators: (pattern, replacement, description)
MUTATIONS = [
    # Arithmetic
    (r'\b\+\b', '-', 'plus_to_minus'),
    (r'\b\-\b', '+', 'minus_to_plus'),
    (r'\b\*\b', '/', 'mul_to_div'),
    (r'\b/\b', '*', 'div_to_mul'),
    # Relational
    (r'\b<\b', '>', 'lt_to_gt'),
    (r'\b>\b', '<', 'gt_to_lt'),
    (r'\b<=\b', '>=', 'le_to_ge'),
    (r'\b>=\b', '<=', 'ge_to_le'),
    (r'\b==\b', '!=', 'eq_to_ne'),
    (r'\b!=\b', '==', 'ne_to_eq'),
    # Logical
    (r'\b&&\b', '||', 'and_to_or'),
    (r'\b\|\|\b', '&&', 'or_to_and'),
    (r'\b!\b', '', 'not_removed'),
    # Constants
    (r'\b0\b', '1', 'zero_to_one'),
    (r'\b1\b', '0', 'one_to_zero'),
    (r'\b-1\b', '1', 'neg_one_to_one'),
    (r'\btrue\b', 'false', 'true_to_false'),
    (r'\bfalse\b', 'true', 'false_to_true'),
    (r'\bNULL\b', '(void*)1', 'null_to_nonnull'),
    # Return values
    (r'return\s+0\b', 'return 1', 'return_zero_to_one'),
    (r'return\s+1\b', 'return 0', 'return_one_to_zero'),
    (r'return\s+NULL\b', 'return (void*)1', 'return_null_to_nonnull'),
]

# Files to exclude from mutation (too large, or not our code)
EXCLUDE_PATTERNS = [
    'cJSON.c',
    'cJSON.h',
]

def should_mutate(filepath: Path) -> bool:
    """Check if file should be mutated."""
    name = filepath.name
    for pattern in EXCLUDE_PATTERNS:
        if pattern in name:
            return False
    return filepath.suffix in ['.c', '.h']


def find_mutable_lines(content: str) -> List[Tuple[int, str, str, str]]:
    """Find lines that can be mutated. Returns (line_num, original, mutated, operator)."""
    lines = content.splitlines(keepends=True)
    mutable = []
    for i, line in enumerate(lines):
        # Skip comments, preprocessor, empty lines
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#'):
            continue
        # Skip string literals for now (too complex)
        if '"' in line and not line.strip().startswith('"'):
            # Has string content, be careful
            pass
        for pattern, replacement, op_name in MUTATIONS:
            if re.search(pattern, line):
                mutated = re.sub(pattern, replacement, line)
                if mutated != line:
                    mutable.append((i, line, mutated, op_name))
    return mutable


def apply_mutation(content: str, line_num: int, mutated_line: str) -> str:
    """Apply a single mutation to content."""
    lines = content.splitlines(keepends=True)
    if 0 <= line_num < len(lines):
        lines[line_num] = mutated_line
    return ''.join(lines)


def compile_and_test(mutant_dir: Path, test_name: str) -> Tuple[bool, str]:
    """Compile and run a specific test against mutant code."""
    # Build the test binary with mutant sources
    cmd = [
        'gcc', '-std=c11', '-Wall', '-Wextra', '-O0', '-g',
        '-I', str(ROOT / 'include'),
        '-I', str(mutant_dir / 'include') if (mutant_dir / 'include').exists() else str(ROOT / 'include'),
        '-o', str(mutant_dir / f'test_{test_name}'),
        str(TEST_DIR / f'test_{test_name}_c.c'),
        str(mutant_dir / 'include' / 'beacon_common.c') if (mutant_dir / 'include' / 'beacon_common.c').exists() else str(ROOT / 'include' / 'beacon_common.c'),
        str(mutant_dir / 'include' / 'config.c') if (mutant_dir / 'include' / 'config.c').exists() else str(ROOT / 'include' / 'config.c'),
        str(mutant_dir / 'include' / 'aes.c') if (mutant_dir / 'include' / 'aes.c').exists() else str(ROOT / 'include' / 'aes.c'),
        str(mutant_dir / 'include' / 'aes_cfb.c') if (mutant_dir / 'include' / 'aes_cfb.c').exists() else str(ROOT / 'include' / 'aes_cfb.c'),
        str(mutant_dir / 'include' / 'cJSON.c') if (mutant_dir / 'include' / 'cJSON.c').exists() else str(ROOT / 'include' / 'cJSON.c'),
        '-lcmocka'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=ROOT)
    if result.returncode != 0:
        return False, f"Compile failed: {result.stderr[:200]}"

    # Run the test
    result = subprocess.run([str(mutant_dir / f'test_{test_name}')], capture_output=True, text=True, timeout=30, cwd=ROOT)
    return result.returncode == 0, result.stdout[:200]


def run_mutation_test() -> Dict:
    """Run mutation testing on all C source files."""
    results = {
        'total_mutants': 0,
        'killed': 0,
        'survived': 0,
        'compile_errors': 0,
        'details': []
    }

    # Find all test files to know what to test
    test_files = list(TEST_DIR.glob('test_*_c.c'))
    test_names = [f.stem.replace('test_', '').replace('_c', '') for f in test_files]

    if not test_names:
        print("No C tests found (test_*_c.c)")
        return results

    print(f"Found C tests: {test_names}")

    # Collect source files to mutate
    source_files = []
    for src_dir in SRC_DIRS:
        if src_dir.exists():
            for f in src_dir.rglob('*.c'):
                if should_mutate(f):
                    source_files.append(f)
            for f in src_dir.rglob('*.h'):
                if should_mutate(f):
                    source_files.append(f)

    print(f"Mutating {len(source_files)} source files...")

    for src_file in source_files:
        content = src_file.read_text()
        mutable_lines = find_mutable_lines(content)

        if not mutable_lines:
            continue

        # Limit mutations per file to keep runtime reasonable
        for line_num, original, mutated, op_name in mutable_lines[:10]:
            results['total_mutants'] += 1

            # Create mutant directory
            with tempfile.TemporaryDirectory() as tmpdir:
                mutant_dir = Path(tmpdir)
                # Copy all source files
                for sf in source_files:
                    rel = sf.relative_to(ROOT)
                    dst = mutant_dir / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if sf == src_file:
                        dst.write_text(apply_mutation(content, line_num, mutated))
                    else:
                        dst.write_text(sf.read_text())

                # Test against each test
                killed = False
                for test_name in test_names:
                    success, output = compile_and_test(mutant_dir, test_name)
                    if not success:
                        killed = True
                        break

                if killed:
                    results['killed'] += 1
                    status = "KILLED"
                else:
                    results['survived'] += 1
                    status = "SURVIVED"

                results['details'].append({
                    'file': str(src_file.relative_to(ROOT)),
                    'line': line_num + 1,
                    'operator': op_name,
                    'original': original.strip()[:80],
                    'mutated': mutated.strip()[:80],
                    'status': status
                })

                print(f"  {status}: {src_file.relative_to(ROOT)}:{line_num+1} ({op_name})")

    return results


def main():
    print("=== C Mutation Testing ===")
    results = run_mutation_test()

    print(f"\n=== Mutation Testing Results ===")
    print(f"Total mutants:  {results['total_mutants']}")
    print(f"Killed:         {results['killed']}")
    print(f"Survived:       {results['survived']}")
    print(f"Compile errors: {results['compile_errors']}")

    if results['total_mutants'] > 0:
        score = (results['killed'] / results['total_mutants']) * 100
        print(f"Mutation score: {score:.1f}%")
        if score < 80:
            print("WARNING: Mutation score below 80% threshold!")
            sys.exit(1)

    # Print surviving mutants details
    if results['survived'] > 0:
        print("\n=== Surviving Mutants (test gaps) ===")
        for d in results['details']:
            if d['status'] == 'SURVIVED':
                print(f"  {d['file']}:{d['line']} [{d['operator']}]")
                print(f"    Original: {d['original']}")
                print(f"    Mutated:  {d['mutated']}")


if __name__ == '__main__':
    main()