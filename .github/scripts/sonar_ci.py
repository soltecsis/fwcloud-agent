"""Same-run Rust evidence for the official scanner; never poll Sonar ourselves."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import urlparse, parse_qs

from ci_reports import lcov, source_inventory

ROOT = Path(__file__).resolve().parents[2]
ACTION = "SonarSource/sonarqube-scan-action@d209202bc7d53ff1cc128f7f907dac145c9d6ae9"
SCANNER = "8.1.0.6389"


def require(condition):
    if not condition:
        raise ValueError("Invalid or incomplete Sonar evidence")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha(path):
    require(path.is_file() and not path.is_symlink())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(root, env):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(re.fullmatch(r"[a-f0-9]{40}", commit) and commit == env.get("ANALYSIS_COMMIT"))
    require(re.fullmatch(r"[\w.-]+/[\w.-]+", env.get("GITHUB_REPOSITORY", ""), re.ASCII))
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", env.get(key, "")))
    require(env.get("GITHUB_EVENT_NAME") in ("push", "pull_request", "workflow_dispatch"))
    require(env.get("GITHUB_REF"))
    return {"repository": env["GITHUB_REPOSITORY"], "source_commit": commit,
            "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"],
            "event": env["GITHUB_EVENT_NAME"], "ref": env["GITHUB_REF"]}


def producer(metadata, ci):
    for key in ("repository", "source_commit", "run_id", "event", "ref"):
        require(metadata.get(key) == ci[key])
    attempt = str(metadata.get("run_attempt", ""))
    require(re.fullmatch(r"[1-9][0-9]*", attempt) and int(attempt) <= int(ci["run_attempt"]))
    return attempt


def clippy_json(path):
    require(path.stat().st_size > 0 and path.stat().st_size < 100 * 1024 * 1024)
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    require(records and all(isinstance(record, dict) for record in records))
    finished = [record for record in records if record.get("reason") == "build-finished"]
    require(len(finished) == 1 and finished[0].get("success") is True)
    # A successful process may not hide a compiler error in partial output.
    require(not any(record.get("reason") == "compiler-message" and
                    record.get("message", {}).get("level") == "error" for record in records))


def clippy(root=ROOT, env=os.environ):
    directory = root / "reports/clippy"
    directory.mkdir(parents=True, exist_ok=True)
    receipt = {"status": "error"}
    code = 1
    for name in ("clippy.json", "analysis.json"):
        (directory / name).unlink(missing_ok=True)
    try:
        receipt.update(identity(root, env))
        rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        version = subprocess.check_output(["rustc", "--version"], cwd=root, env=env, text=True)
        require(version.startswith("rustc " + rust + " "))
        with (directory / "clippy.json").open("w") as output:
            result = subprocess.run(["cargo", "clippy", "--all-targets", "--locked", "--message-format=json",
                                     "--", "-D", "warnings"], cwd=root, env=env, stdout=output)
        code = result.returncode
        receipt.update(exit_code=code, rust=rust, report_sha256=sha(directory / "clippy.json"))
        if code == 0:
            clippy_json(directory / "clippy.json")
            receipt["status"] = "success"
        return code
    finally:
        write(directory / "analysis.json", receipt)


def branch(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_.-]{0,199}", value))
    return value


def prepare(root=ROOT, env=os.environ):
    ci = identity(root, env)
    key = env.get("SONAR_PROJECT_KEY", "")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", key))
    source_branch = branch(env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME"))
    args = [f"-Dsonar.projectKey={key}", f"-Dsonar.scm.revision={ci['source_commit']}"]
    if ci["event"] == "pull_request":
        number = env.get("PR_NUMBER", "")
        require(re.fullmatch(r"[1-9][0-9]*", number))
        args.extend([f"-Dsonar.pullrequest.key={number}", f"-Dsonar.pullrequest.branch={source_branch}",
                     f"-Dsonar.pullrequest.base={branch(env.get('GITHUB_BASE_REF'))}"])
    else:
        reference = branch(env.get("SONAR_REFERENCE_BRANCH"))
        args.append(f"-Dsonar.branch.name={source_branch}")
        # A reference branch must not refer to itself; its baseline is configured on Sonar.
        if source_branch != reference:
            args.append(f"-Dsonar.newCode.referenceBranch={reference}")
    for tree in ("src", "tests"):
        directory = root / tree
        require(directory.is_dir() and not directory.is_symlink())
        require(not any(path.is_symlink() for path in directory.rglob("*")))
    cov = root / "coverage-input"
    lint = root / "clippy-input"
    coverage = json.loads((cov / "analysis.json").read_text())
    clippy_report = json.loads((lint / "analysis.json").read_text())
    coverage_attempt = producer(coverage, ci)
    clippy_attempt = producer(clippy_report, ci)
    require(coverage.get("producer_attempt") == coverage_attempt)
    require(coverage.get("accepted_baseline") is True and coverage.get("test_status") == "success" and
            coverage.get("validation_status") == "success" and coverage.get("validation_errors") == [])
    require(coverage.get("lcov_sha256") == sha(cov / "lcov.info"))
    records = lcov(cov / "lcov.info", root)
    require(records.keys() <= source_inventory(root, env))
    rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    pins = tomllib.loads((root / ".github/report-tools.toml").read_text())
    require(coverage.get("versions") == {"rustc": rust, "cargo": rust,
            "cargo-nextest": pins["cargo-nextest"]["version"], "cargo-llvm-cov": pins["cargo-llvm-cov"]["version"]})
    require(clippy_report.get("status") == "success" and type(clippy_report.get("exit_code")) is int and
            clippy_report.get("exit_code") == 0 and
            clippy_report.get("rust") == rust and clippy_report.get("report_sha256") == sha(lint / "clippy.json"))
    clippy_json(lint / "clippy.json")
    result = {**ci, "projectKey": key, "branch": source_branch,
              "coverageProducerAttempt": coverage_attempt, "clippyProducerAttempt": clippy_attempt,
              "lcovSha256": sha(cov / "lcov.info"), "clippySha256": sha(lint / "clippy.json"),
              "settingsSha256": sha(root / "sonar-project.properties"), "preparation": "success"}
    write(root / "reports/sonar/context.json", result)
    with open(env["GITHUB_OUTPUT"], "a") as output:
        output.write("args=" + " ".join(args) + "\n")
    return result


def record(root=ROOT, env=os.environ):
    result = {"preparation": "failed_or_incomplete"}
    context = root / "reports/sonar/context.json"
    if env.get("PREPARE_OUTCOME") == "success" and context.is_file():
        result = json.loads(context.read_text())
        require(all(result.get(k) == v for k, v in identity(root, env).items()))
    outcome = env.get("SCAN_OUTCOME", "skipped")
    result.update(action=ACTION, scannerVersion=SCANNER, scanOutcome=outcome,
                  qualityGate="PASSED" if outcome == "success" and result.get("preparation") == "success"
                  else "FAILED_OR_INCOMPLETE")
    task = root / ".scannerwork/report-task.txt"
    if task.is_file():
        fields = dict(line.split("=", 1) for line in task.read_text().splitlines() if "=" in line)
        url = urlparse(fields.get("dashboardUrl", ""))
        query = parse_qs(url.query, keep_blank_values=True)
        if (url.scheme == "https" and url.netloc == "sonarcloud.io" and url.path == "/dashboard" and
                query.get("id") == [result.get("projectKey")] and
                set(query) <= {"id", "branch", "pullRequest"} and not url.fragment and
                ("branch" not in query or query["branch"] == [result.get("branch")]) and
                ("pullRequest" not in query or len(query["pullRequest"]) == 1 and
                 re.fullmatch(r"[1-9][0-9]*", query["pullRequest"][0]))):
            result["dashboardUrl"] = url.geturl()
    write(root / "reports/sonar/metadata.json", result)
    text = (f"## Agent SonarQube analysis\n\nScanner: {SCANNER}\n\n"
            f"Preparation: {result['preparation']}\n\nQuality Gate: **{result['qualityGate']}**\n\n"
            f"Revision: `{result.get('source_commit', 'unavailable')}`\n\n"
            f"Coverage producer attempt: {result.get('coverageProducerAttempt', 'unavailable')}; "
            f"Clippy producer attempt: {result.get('clippyProducerAttempt', 'unavailable')}\n")
    if result.get("dashboardUrl"):
        text += f"\n[Analysis details]({result['dashboardUrl']})\n"
    print(text)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(text)
    return result


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["clippy"]:
            sys.exit(clippy())
        elif sys.argv[1:] == ["prepare"]:
            prepare()
        elif sys.argv[1:] == ["record"]:
            record()
        else:
            sys.exit("Expected clippy, prepare or record")
    except Exception:
        sys.exit("Sonar evidence control failed; inspect configuration and producer artifacts.")
