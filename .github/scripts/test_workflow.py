"""Exercise the actual aggregate command, including absent and skipped jobs."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows/main.yml"


class AggregateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = WORKFLOW.read_text()
        aggregate = workflow.split("\n  agent-ci:\n", 1)[1].split("\n  deb-package:\n", 1)[0]
        cls.required = re.search(r"needs: \[([^\]]+)\]", aggregate).group(1).split(", ")
        cls.command = textwrap.dedent(aggregate.split("python3 - <<'PY'\n", 1)[1].split("          PY", 1)[0])

    def invoke(self, results):
        return subprocess.run(
            [sys.executable, "-c", self.command],
            env={**os.environ, "REQUIRED_RESULTS": json.dumps(results)},
            capture_output=True, text=True,
        )

    def successful_results(self):
        return {job: {"result": "success"} for job in self.required}

    def test_all_required_jobs_succeed(self):
        result = self.invoke(self.successful_results())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_non_success_result_blocks(self):
        for job in self.required:
            for outcome in ("failure", "cancelled", "skipped", "", None):
                with self.subTest(job=job, outcome=outcome):
                    results = self.successful_results()
                    results[job]["result"] = outcome
                    self.assertNotEqual(self.invoke(results).returncode, 0)

    def test_missing_job_or_result_blocks(self):
        for job in self.required:
            with self.subTest(job=job):
                results = self.successful_results()
                del results[job]
                self.assertNotEqual(self.invoke(results).returncode, 0)
                results[job] = {}
                self.assertNotEqual(self.invoke(results).returncode, 0)

    def test_unexpected_jobs_block(self):
        results = self.successful_results()
        results["unreviewed"] = {"result": "success"}
        self.assertNotEqual(self.invoke(results).returncode, 0)


if __name__ == "__main__":
    unittest.main()
