"""Compile and compare the observable execution of original and decompiled Python sources."""

from __future__ import annotations

import argparse
import ast
import difflib
import math
import os
from pathlib import Path
import subprocess
import sys
import tokenize


MARKERS = ("<?>", "# error", "# incomplete reconstruction:")
MAX_DIFF_LINES = 80
RUNNER = r"""
import pathlib
import sys
import tokenize
import types

program_path, probe_path, display_path = sys.argv[1:4]
sys.argv = [display_path]
with tokenize.open(program_path) as source_file:
    source = source_file.read()
module_name = "_roundtrip_target" if probe_path else "__main__"
module = types.ModuleType(module_name)
module.__file__ = display_path
module.__package__ = None
module.__spec__ = None
sys.modules[module_name] = module
namespace = module.__dict__
sys.path.insert(0, str(pathlib.Path.cwd()))
exec(compile(source, display_path, "exec", dont_inherit=True), namespace, namespace)
if probe_path:
    with tokenize.open(probe_path) as probe_file:
        probe = probe_file.read()
    exec(compile(probe, probe_path, "exec", dont_inherit=True), namespace, namespace)
"""


class ModuleReturnVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.function_depth = 0
        self.lines: list[int] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1

    def visit_Return(self, node: ast.Return) -> None:
        if self.function_depth == 0:
            self.lines.append(node.lineno)
        self.generic_visit(node)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile, scan, and behaviorally compare original and reconstructed Python sources."
    )
    parser.add_argument("original", type=Path, help="original .py source")
    parser.add_argument("reconstructed", type=Path, help="decompiled .py source")
    parser.add_argument(
        "--target",
        required=True,
        help="required Python major.minor target, for example 3.14",
    )
    parser.add_argument(
        "--probe",
        type=Path,
        help="optional Python script run in each program's global namespace",
    )
    parser.add_argument(
        "--cwd",
        type=Path,
        help="working directory for both executions (defaults to the original source directory)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-program execution timeout in seconds (default: 30)",
    )
    return parser.parse_args()


def read_source(path: Path) -> str:
    with tokenize.open(path) as source_file:
        return source_file.read()


def compile_source(path: Path, source: str) -> list[str]:
    try:
        compile(source, str(path), "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        return [f"{path}: compile failed: {error}"]
    return []


def reconstructed_source_issues(path: Path, source: str) -> list[str]:
    issues: list[str] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        found_markers = [marker for marker in MARKERS if marker in line]
        if found_markers:
            issues.append(
                f"{path}:{line_number}: reconstruction marker(s) "
                + ", ".join(repr(marker) for marker in found_markers)
            )

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return issues
    visitor = ModuleReturnVisitor()
    visitor.visit(tree)
    issues.extend(
        f"{path}:{line_number}: return outside a function"
        for line_number in visitor.lines
    )
    return issues


def execute(
    source_path: Path,
    display_path: Path,
    probe_path: Path | None,
    cwd: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    command = [
        sys.executable,
        "-c",
        RUNNER,
        str(source_path),
        str(probe_path) if probe_path else "",
        str(display_path),
    ]
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def print_difference(label: str, original: str, reconstructed: str) -> None:
    print(f"{label} differs:")
    difference = list(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            reconstructed.splitlines(keepends=True),
            fromfile="original",
            tofile="reconstructed",
        )
    )
    if not difference:
        print("  values differ")
        return
    shown = difference[:MAX_DIFF_LINES]
    sys.stdout.writelines(shown)
    if len(difference) > MAX_DIFF_LINES:
        print(f"... diff truncated ({len(difference) - MAX_DIFF_LINES} more lines)")


def main() -> int:
    args = parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print("error: --timeout must be a finite number greater than zero", file=sys.stderr)
        return 2
    if args.target != f"{sys.version_info.major}.{sys.version_info.minor}":
        print(
            f"error: target Python {args.target} does not match the running "
            f"interpreter {sys.version_info.major}.{sys.version_info.minor}",
            file=sys.stderr,
        )
        return 2

    paths = [args.original, args.reconstructed]
    if args.probe:
        paths.append(args.probe)
    for path in paths:
        if not path.is_file():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2

    try:
        original_source = read_source(args.original)
        reconstructed_source = read_source(args.reconstructed)
        probe_source = read_source(args.probe) if args.probe else None
    except (OSError, SyntaxError, UnicodeError) as error:
        print(f"error: cannot read input source: {error}", file=sys.stderr)
        return 2

    compile_issues = compile_source(args.original, original_source)
    compile_issues.extend(compile_source(args.reconstructed, reconstructed_source))
    if probe_source is not None:
        compile_issues.extend(compile_source(args.probe, probe_source))
    static_issues = reconstructed_source_issues(args.reconstructed, reconstructed_source)
    if compile_issues:
        for issue in compile_issues + static_issues:
            print(f"FAIL: {issue}", file=sys.stderr)
        return 1

    for issue in static_issues:
        print(f"FAIL: {issue}", file=sys.stderr)

    cwd = args.cwd.resolve() if args.cwd else args.original.resolve().parent
    display_path = args.original.resolve()
    try:
        original_run = execute(
            args.original.resolve(), display_path, args.probe.resolve() if args.probe else None,
            cwd, args.timeout,
        )
        reconstructed_run = execute(
            args.reconstructed.resolve(), display_path, args.probe.resolve() if args.probe else None,
            cwd, args.timeout,
        )
    except subprocess.TimeoutExpired as error:
        print(f"FAIL: program execution exceeded {args.timeout:g} seconds: {error.cmd}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"FAIL: could not execute Python program: {error}", file=sys.stderr)
        return 1

    mismatches = []
    if original_run.returncode != reconstructed_run.returncode:
        mismatches.append("exit status")
    if original_run.stdout != reconstructed_run.stdout:
        mismatches.append("stdout")
        print_difference("stdout", original_run.stdout, reconstructed_run.stdout)
    if original_run.stderr != reconstructed_run.stderr:
        mismatches.append("stderr")
        print_difference("stderr", original_run.stderr, reconstructed_run.stderr)

    if mismatches:
        print("FAIL: execution differs in " + ", ".join(mismatches))
        print(
            f"  exit status: original={original_run.returncode}, "
            f"reconstructed={reconstructed_run.returncode}"
        )
    else:
        print(
            f"Execution results match: exit status={original_run.returncode}, "
            f"stdout={len(original_run.stdout)} chars, stderr={len(original_run.stderr)} chars"
        )
    if static_issues or mismatches:
        return 1

    print(
        f"PASS: Python {sys.version_info.major}.{sys.version_info.minor}; "
        "both sources compile, reconstruction markers are absent, and executions match"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
