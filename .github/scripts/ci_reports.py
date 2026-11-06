#!/usr/bin/env python3
"""Validate fresh test/LLVM evidence and emit aggregate-only CI provenance."""

import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
MINIMUM = 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    value = json.loads(path.read_text(), parse_constant=lambda _: require(False, "Nonfinite JSON"))
    require(isinstance(value, dict), "Expected JSON object")
    return value


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def command_output(args, root, env):
    return subprocess.check_output(args, cwd=root, env=env, text=True).strip()


def context(root=ROOT, env=os.environ):
    fields = {key: env.get(name, "") for key, name in {
        "repository": "GITHUB_REPOSITORY", "source_commit": "ANALYSIS_COMMIT",
        "run_id": "GITHUB_RUN_ID", "run_attempt": "GITHUB_RUN_ATTEMPT",
        "event": "GITHUB_EVENT_NAME", "ref": "GITHUB_REF",
    }.items()}
    require(re.fullmatch(r"[\w.-]+/[\w.-]+", fields["repository"], re.ASCII), "Invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", fields["source_commit"]), "Invalid analyzed commit")
    for name in ("run_id", "run_attempt"):
        require(re.fullmatch(r"[1-9][0-9]*", fields[name]), "Invalid run context")
    require(fields["event"] and fields["ref"], "Missing event or reference")
    require(Path(command_output(["git", "rev-parse", "--show-toplevel"], root, env)).resolve()
            == root.resolve(), "Unverified checkout root")
    require(command_output(["git", "rev-parse", "HEAD"], root, env) == fields["source_commit"],
            "Checkout differs from ANALYSIS_COMMIT")
    rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    pins = tomllib.loads((root / ".github/report-tools.toml").read_text())
    versions = {}
    for name, args, expected in (
        ("rustc", ["rustc", "--version"], rust),
        ("cargo", ["cargo", "--version"], rust),
        ("cargo-nextest", ["cargo", "nextest", "--version"], pins["cargo-nextest"]["version"]),
        ("cargo-llvm-cov", ["cargo", "llvm-cov", "--version"], pins["cargo-llvm-cov"]["version"]),
    ):
        actual = command_output(args, root, env)
        # Cargo plugins may prefix their version with the subcommand name.
        require(re.search(rf"(?:^|\s){re.escape(name)} {re.escape(expected)}(?:\s|$)", actual),
                "Installed tool differs from reporting pins")
        versions[name] = expected
    return fields | {"versions": versions}


def verify_identity(record, expected):
    require(all(record.get(key) == value for key, value in expected.items()),
            "Stale or mismatched execution metadata")


def source_inventory(root, env):
    paths = command_output(["git", "ls-files", "-z", "--", "src"], root, env).split("\0")
    return {name for name in paths if name.endswith(".rs")}


def source_path(value, root, normalize=False):
    require(isinstance(value, str) and value and "\\" not in value and "\x00" not in value,
            "Invalid source path")
    path = PurePosixPath(value)
    require(".." not in path.parts and not re.match(r"^[A-Za-z]:", value), "Traversing source path")
    if path.is_absolute():
        require(normalize, "Absolute source path")
        try:
            value = Path(value).relative_to(root.resolve()).as_posix()
        except ValueError:
            raise ValueError("Source outside checkout") from None
    require(value.startswith("src/") and value.endswith(".rs"), "Nonapplication coverage source")
    path = PurePosixPath(value)
    require(not {"tests", "target", "generated", "vendor"}.intersection(path.parts)
            and path.name != "tests.rs" and not path.stem.endswith(("_tests", "-tests")),
            "Test or generated coverage source")
    actual = root / value
    require(actual.is_file() and actual.resolve() == actual.absolute(),
            "Missing or symlinked original source")
    return value


def junit(path):
    data = path.read_text(encoding="utf-8-sig")
    require(data.strip(), "Empty JUnit")
    require("\x00" not in data and "<!DOCTYPE" not in data.upper() and "<!ENTITY" not in data.upper(),
            "Unsafe JUnit XML")
    root = ET.fromstring(data)
    require(root.tag in ("testsuites", "testsuite"), "Invalid JUnit root")
    suites = list(root) if root.tag == "testsuites" else [root]
    require(suites and all(s.tag == "testsuite" for s in suites), "Invalid JUnit suites")
    total = dict(tests=0, passed=0, failed=0, errors=0, skipped=0)
    for suite in suites:
        counts = dict(tests=0, passed=0, failed=0, errors=0, skipped=0)
        require(suite.find("error") is None, "JUnit suite execution error")
        require(all(child.tag in {"testcase", "properties", "system-out", "system-err"} for child in suite),
                "Invalid JUnit suite structure")
        identities = set()
        for case in suite.findall("testcase"):
            identity = (case.get("classname"), case.get("name"))
            require(identity[1] and identity not in identities, "Duplicate or unnamed JUnit case")
            identities.add(identity)
            require(all(child.tag in {"failure", "error", "skipped", "properties", "system-out", "system-err"}
                        for child in case), "Invalid JUnit case structure")
            states = [name for name in ("failure", "error", "skipped") if case.find(name) is not None]
            require(len(states) <= 1, "Contradictory JUnit case")
            state = {"failure": "failed", "error": "errors", "skipped": "skipped"}.get(
                states[0] if states else "", "passed")
            counts[state] += 1
            counts["tests"] += 1
        for attr, name in (("tests", "tests"), ("failures", "failed"),
                           ("errors", "errors"), ("skipped", "skipped")):
            if attr in suite.attrib:
                require(suite.get(attr) == str(counts[name]), "Inconsistent JUnit suite counts")
        for name in total:
            total[name] += counts[name]
    for attr, name in (("tests", "tests"), ("failures", "failed"),
                       ("errors", "errors"), ("skipped", "skipped")):
        if attr in root.attrib:
            require(root.get(attr) == str(total[name]), "Inconsistent JUnit total counts")
    require(total["tests"] - total["skipped"] > 0, "Zero executed tests")
    return total


def lcov(path, root, normalize=False):
    records, current, output = {}, None, []
    for line in path.read_text().splitlines():
        if line.startswith("SF:"):
            require(current is None, "Unterminated LCOV record")
            name = source_path(line[3:], root, normalize)
            require(name not in records, "Duplicate LCOV source")
            current = {"name": name, "lines": {}, "declared": {},
                       "source_lines": len((root / name).read_text().splitlines())}
            line = "SF:" + name
        elif line == "end_of_record":
            require(current is not None, "Empty LCOV record")
            lines = current["lines"]
            totals = current["declared"]
            require(set(totals) == {"LF", "LH"} and 0 <= totals["LH"] <= totals["LF"], "Invalid LCOV totals")
            require(lines or totals["LF"] == 0, "LCOV lacks executable line records")
            # LLVM counts macro expansion lines in LF/LH, but exports DA for
            # physical source lines. Verify both bounds here and exact native
            # totals against JSON below; never invent extra DA source locations.
            covered = sum(count > 0 for count in lines.values())
            require(totals["LF"] >= len(lines) and totals["LH"] >= covered
                    and totals["LF"] - totals["LH"] >= len(lines) - covered, "Invalid LCOV line totals")
            records[current["name"]] = totals
            current = None
        elif line.startswith("TN:") and current is None:
            pass
        else:
            require(current is not None and ":" in line, "Invalid LCOV record")
            kind, value = line.split(":", 1)
            if kind == "DA":
                parts = value.split(",")
                require(len(parts) in (2, 3) and all(p.isdigit() for p in parts[:2]), "Invalid LCOV DA")
                number, count = map(int, parts[:2])
                require(0 < number <= current["source_lines"]
                        and number not in current["lines"], "Invalid LCOV source line")
                current["lines"][number] = count
            elif kind in ("LF", "LH"):
                require(value.isdigit() and kind not in current["declared"], "Invalid LCOV totals")
                current["declared"][kind] = int(value)
            elif kind in ("FNF", "FNH", "BRF", "BRH"):
                require(value.isdigit(), "Invalid LCOV counter")
            elif kind in ("FN", "FNDA"):
                require(re.fullmatch(r"[0-9]+,.+", value), "Invalid LCOV function")
            elif kind == "BRDA":
                require(re.fullmatch(r"[0-9]+,[0-9]+,[0-9]+,(?:[0-9]+|-)", value), "Invalid LCOV branch")
            else:
                raise ValueError("Unknown LCOV record")
        output.append(line)
    require(current is None and records and sum(r["LF"] for r in records.values()) > 0,
            "Missing executable LCOV sources")
    if normalize:
        path.write_text("\n".join(output) + "\n")
    return records


def coverage(path, records, root, normalize=False):
    report = read_json(path)
    require(report.get("type") == "llvm.coverage.json.export" and isinstance(report.get("version"), str)
            and re.fullmatch(r"[23]\.[0-9]+\.[0-9]+", report["version"]), "Invalid LLVM JSON")
    require(isinstance(report.get("data"), list) and len(report["data"]) == 1, "Invalid LLVM data")
    data = report["data"][0]
    require(isinstance(data, dict) and isinstance(data.get("files"), list), "Invalid LLVM files")
    files = {}
    for file in data["files"]:
        require(isinstance(file, dict), "Invalid LLVM file")
        name = source_path(file["filename"], root, normalize)
        require(name not in files, "Duplicate LLVM source")
        file["filename"] = name
        files[name] = line_metrics(file["summary"]["lines"])
    require(files.keys() == records.keys(), "LCOV and LLVM sources differ")
    for name, metrics in files.items():
        require(metrics["count"] == records[name]["LF"] and metrics["covered"] == records[name]["LH"],
                "LCOV and LLVM file metrics differ")
    total = line_metrics(data["totals"]["lines"])
    require(total["count"] > 0 and total["count"] == sum(f["count"] for f in files.values())
            and total["covered"] == sum(f["covered"] for f in files.values()), "Invalid LLVM aggregate")
    # --skip-functions avoids a second, redundant set of absolute source paths.
    require(not data.get("functions"), "LLVM JSON must omit redundant function data")
    if normalize:
        write_json(path, report)
    return total


def line_metrics(value):
    count, covered, percent = value["count"], value["covered"], value["percent"]
    require(type(count) is int and type(covered) is int and 0 <= covered <= count, "Invalid line counts")
    require(type(percent) in (int, float) and math.isfinite(percent) and 0 <= percent <= 100,
            "Invalid line percentage")
    computed = 100 * covered / count if count else 0
    require(abs(computed - percent) < 0.011, "Inconsistent line percentage")
    return {"count": count, "covered": covered, "percent": computed}


def verify_analysis(analysis, expected, checksum):
    verify_identity(analysis, expected)
    require(analysis.get("producer_attempt") == expected["run_attempt"], "Mismatched coverage producer")
    require(analysis.get("lcov_sha256") == checksum, "LCOV SHA-256 mismatch")


def html_report(path):
    class ReportHTML(HTMLParser):
        def __init__(self):
            super().__init__()
            self.started, self.ended = set(), set()

        def handle_starttag(self, tag, attrs):
            self.started.add(tag)

        def handle_endtag(self, tag):
            self.ended.add(tag)

    parser = ReportHTML()
    parser.feed(path.read_text())
    parser.close()
    require({"html", "body"} <= parser.started & parser.ended, "Invalid HTML report")


def summary(metadata):
    counts = metadata.get("tests") or {}
    percentage = metadata.get("coverage", {}).get("percent")
    rows = [
        ("Analyzed commit", metadata.get("source_commit", "unavailable")),
        ("Tests", counts.get("tests", "unavailable")), ("Passed", counts.get("passed", "unavailable")),
        ("Failed", counts["failed"] + counts["errors"] if counts else "unavailable"),
        ("Skipped", counts.get("skipped", "unavailable")),
        ("Test execution", metadata["test_status"]),
        ("Line coverage", f"{percentage:.2f}%" if percentage is not None else "unavailable"),
        ("Required minimum", f"{MINIMUM}%"), ("Report validation", metadata["validation_status"]),
    ]
    return "| Metric | Result |\n| --- | --- |\n" + "".join(f"| {a} | {b} |\n" for a, b in rows)


def validate(root=ROOT, env=os.environ):
    started = time.monotonic()
    reports = root / "reports"
    errors, identity = [], {}
    counts, metrics, execution = {}, {}, {}

    def check(name, action):
        try:
            return action()
        except (ValueError, OSError, KeyError, TypeError, ET.ParseError, subprocess.SubprocessError):
            # Never copy XML payloads, test names, source paths or environment into the summary/errors.
            errors.append(name)
            return None

    identity = check("checkout/tool context", lambda: context(root, env)) or {}
    execution = check("execution metadata", lambda: read_json(reports / "tests/execution.json")) or {}

    def execution_valid():
        require(identity, "Missing verified context")
        verify_identity(execution, identity)
        require(execution["completed"] is True, "Incomplete execution")
        for stage in ("clean", "build", "discovery", "profile_cleanup", "test", "lcov", "json", "html", "gate", "normalization"):
            require(type(execution["commands"][stage]["exit_code"]) is int
                    and execution["commands"][stage]["exit_code"] == 0, "Unsuccessful command")
    check("runner/report command completion", execution_valid)
    for name in ("tests/junit.xml", "coverage/lcov.info", "coverage/coverage.json", "coverage/html/index.html"):
        check("report digest: " + name, lambda name=name: require(
            execution["report_sha256"][name] == hashlib.sha256((reports / name).read_bytes()).hexdigest(),
            "Report changed after production"))
    counts = check("JUnit evidence", lambda: junit(reports / "tests/junit.xml")) or {}
    check("test results", lambda: require(counts and not counts["failed"] and not counts["errors"], "Failed tests"))
    check("test discovery", lambda: require(counts and counts["tests"] == execution["discovery"]["tests"]
                                           and execution["discovery"]["doctests"] == 0, "Incomplete test scope"))
    records = check("LCOV evidence/scope", lambda: lcov(reports / "coverage/lcov.info", root))
    if records:
        check("original source inventory", lambda: require(
            records.keys() <= source_inventory(root, env), "Coverage includes untracked/generated sources"))
        metrics = check("LLVM JSON evidence", lambda: coverage(
            reports / "coverage/coverage.json", records, root)) or {}
    else:
        errors.append("LLVM JSON evidence")
    check("line coverage gate", lambda: require(metrics and metrics["count"] > 0
                                                and metrics["percent"] >= MINIMUM, "Coverage below minimum"))
    check("HTML evidence", lambda: html_report(reports / "coverage/html/index.html"))
    checksum = check("LCOV checksum", lambda: hashlib.sha256((reports / "coverage/lcov.info").read_bytes()).hexdigest())
    analysis_path = reports / "coverage/analysis.json"
    if analysis_path.exists():
        check("prior coverage identity/checksum", lambda: verify_analysis(read_json(analysis_path), identity, checksum))
    commands = execution.get("commands", {})
    test_command = commands.get("test", {}) if isinstance(commands, dict) else {}
    test_command = test_command if isinstance(test_command, dict) else {}
    timings = execution.get("timings_seconds", {})
    timings = timings if isinstance(timings, dict) else {}
    test_ok = bool(identity and counts and not counts["failed"] and not counts["errors"]
                   and type(test_command.get("exit_code")) is int and test_command["exit_code"] == 0
                   and execution.get("completed") is True)
    result = identity | {
        "schema_version": 1, "test_status": "success" if test_ok else "failed_or_incomplete",
        "tests": counts, "coverage": metrics, "minimum_line_coverage": MINIMUM,
        "validation_status": "failed" if errors else "success", "validation_errors": errors,
        "timings_seconds": timings | {"validation": time.monotonic() - started},
    }
    write_json(reports / "coverage/coverage-summary.json", {"lines": metrics, "minimum": MINIMUM})
    write_json(analysis_path, identity | {
        "schema_version": 1, "producer_attempt": identity.get("run_attempt"),
        "coverage": metrics, "test_status": result["test_status"], "lcov_sha256": checksum,
        "validation_status": result["validation_status"], "validation_errors": errors,
        "accepted_baseline": not errors,
    })
    write_json(reports / "metadata.json", result)
    if env.get("GITHUB_STEP_SUMMARY"):
        with Path(env["GITHUB_STEP_SUMMARY"]).open("a") as output:
            output.write(summary(result))
    print(f"Report validation: {result['validation_status']}")
    for error in errors:
        print(f"Invalid evidence: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(validate())
