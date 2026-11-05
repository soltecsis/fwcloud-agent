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
        cls.aggregate = aggregate
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

    def test_phase_one_requires_both_quality_and_test_even_after_failure(self):
        self.assertEqual(set(self.required), {"quality", "test"})
        self.assertIn("if: ${{ always() }}", self.aggregate)
        self.assertNotIn("continue-on-error", self.aggregate)

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


class PackagingGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jobs = WORKFLOW.read_text().split("\njobs:\n", 1)[1]
        sections = re.split(r"^  ([\w-]+):\n", jobs, flags=re.MULTILINE)
        cls.jobs = dict(zip(sections[1::2], sections[2::2]))

    def needs(self, job):
        return set(re.search(r"needs: \[([^\]]+)\]", self.jobs[job]).group(1).split(", "))

    def test_packages_preserve_audit_and_coverage_gates(self):
        for job in ("deb-package", "rpm-package"):
            with self.subTest(job=job):
                self.assertEqual(self.needs(job), {"agent-ci", "security_audit", "coverage"})
                self.assertNotIn("if:", self.jobs[job].split("steps:", 1)[0])

    def test_dependency_graph_does_not_reference_removed_jobs(self):
        self.assertNotIn("checks", self.jobs)
        self.assertNotIn("build", self.jobs)
        for job, section in self.jobs.items():
            if "needs:" in section:
                with self.subTest(job=job):
                    self.assertLessEqual(self.needs(job), self.jobs.keys())

    def test_publication_remains_restricted_to_main_pushes_after_packages(self):
        publishers = ("deb-to-fwcloud", "rpm-to-fwcloud",
                      "deb-to-packagecloud", "rpm-to-packagecloud")
        for job in publishers:
            with self.subTest(job=job):
                self.assertEqual(self.needs(job), {"agent-ci", "deb-package", "rpm-package"})
                self.assertIn("github.event_name == 'push'", self.jobs[job])
                self.assertIn("github.ref == 'refs/heads/main'", self.jobs[job])
                self.assertIn("github.repository == 'soltecsis/fwcloud-agent'", self.jobs[job])
        for job, section in self.jobs.items():
            if job not in publishers:
                with self.subTest(job=job):
                    self.assertNotIn("secrets.", section)


if __name__ == "__main__":
    unittest.main()
