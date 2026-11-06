#!/usr/bin/env python3
"""Compare completed hosted jobs exported by gh run view --json jobs,headSha,url."""

from datetime import datetime
import json
from pathlib import Path
import sys


TEST = "FWCloud-Agent Test"
COVERAGE = "Rust coverage"


def duration(item):
    value = (datetime.fromisoformat(item["completedAt"]) - datetime.fromisoformat(item["startedAt"])).total_seconds()
    if value < 0:
        raise ValueError("Invalid execution timestamps")
    return value


def compare(previous, replacement):
    old = {job["name"]: job for job in previous["jobs"] if job["name"] in (TEST, COVERAGE)}
    new = {job["name"]: job for job in replacement["jobs"] if job["name"] in (TEST, COVERAGE)}
    if set(old) != {TEST, COVERAGE} or set(new) != {TEST}:
        raise ValueError("Expected two previous jobs and one replacement job")
    if any(job["conclusion"] != "success" for job in [*old.values(), *new.values()]):
        raise ValueError("Compare only complete successful executions")
    old_durations = {name: duration(job) for name, job in old.items()}
    new_duration = duration(new[TEST])
    return {
        "previous_run": previous["url"], "previous_commit": previous["headSha"],
        "replacement_run": replacement["url"], "replacement_commit": replacement["headSha"],
        "previous_jobs_seconds": old_durations, "previous_total_seconds": sum(old_durations.values()),
        "previous_longest_job_seconds": max(old_durations.values()),
        "replacement_seconds": new_duration,
        "replacement_steps_seconds": {step["name"]: duration(step) for step in new[TEST]["steps"]},
        "within_previous_total": new_duration <= sum(old_durations.values()),
        "within_previous_longest_job": new_duration <= max(old_durations.values()),
    }


if __name__ == "__main__":
    try:
        result = compare(*(json.loads(Path(path).read_text()) for path in sys.argv[1:]))
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["within_previous_total"] and result["within_previous_longest_job"] else 1)
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit("Usage: ci_performance.py previous.json replacement.json (completed successful hosted runs)")
