import unittest
import uuid

from backend.evaluation_metrics import (
    _alert_dedup_rate,
    _diff_between_runs,
    _explainability_coverage,
    _prioritization_quality,
)
from backend.db import SessionLocal
from backend.models import Asset, Finding, ScanRun, Site


class _AlertStub:
    def __init__(self, site_id, trigger_type, title, detail, acknowledged=False):
        self.site_id = site_id
        self.trigger_type = trigger_type
        self.title = title
        self.detail = detail
        self.acknowledged = acknowledged


class EvaluationMetricTests(unittest.TestCase):
    def test_diff_between_runs_uses_explicit_run_order(self):
        site_id = f"eval-test-{uuid.uuid4()}"
        run_a = f"run-a-{uuid.uuid4()}"
        run_b = f"run-b-{uuid.uuid4()}"
        db = SessionLocal()
        try:
            db.add(
                Site(
                    site_id=site_id,
                    name="Eval Test",
                    primary_domain="127.0.0.1",
                    allowed_scopes="127.0.0.1",
                    policy="safe",
                    schedule="manual",
                    auth_confirmed=True,
                )
            )
            db.commit()
            db.add_all(
                [
                    ScanRun(run_id=run_a, site_id=site_id, scope="127.0.0.1", profile="safe", status="done", progress=100),
                    ScanRun(run_id=run_b, site_id=site_id, scope="127.0.0.1", profile="safe", status="done", progress=100),
                ]
            )
            db.commit()
            db.add(
                Asset(
                    site_id=site_id,
                    run_id=run_a,
                    host="127.0.0.1",
                    ip="127.0.0.1",
                    open_ports=1,
                    ports_json="[8000]",
                )
            )
            db.add(
                Asset(
                    site_id=site_id,
                    run_id=run_b,
                    host="127.0.0.1",
                    ip="127.0.0.1",
                    open_ports=2,
                    ports_json="[8000, 8080]",
                )
            )
            db.add(
                Finding(
                    site_id=site_id,
                    run_id=run_b,
                    cve_id="CVE-TEST-NEW",
                    severity="HIGH",
                    cvss=8.8,
                    affected_assets=1,
                    evidence="seeded finding",
                )
            )
            db.commit()

            diff = _diff_between_runs(run_a, run_b, db)
            self.assertEqual(diff["run_a"], run_a)
            self.assertEqual(diff["run_b"], run_b)
            self.assertEqual(diff["new_findings"], ["CVE-TEST-NEW"])
            self.assertEqual(diff["resolved_findings"], [])
            self.assertEqual(diff["port_changes"], [{"host": "127.0.0.1", "old": [8000], "new": [8000, 8080]}])
        finally:
            db.rollback()
            db.query(Finding).filter(Finding.site_id == site_id).delete(synchronize_session=False)
            db.query(Asset).filter(Asset.site_id == site_id).delete(synchronize_session=False)
            db.query(ScanRun).filter(ScanRun.site_id == site_id).delete(synchronize_session=False)
            db.query(Site).filter(Site.site_id == site_id).delete(synchronize_session=False)
            db.commit()
            db.close()

    def test_explainability_coverage_full_when_required_fields_are_generatable(self):
        findings = [
            {
                "cve_id": "CVE-TEST-1000",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "epss": 0.72,
                "kev": 1,
                "exploit": 1,
                "affected_assets": 1,
                "evidence": "127.0.0.1:8080 apache 2.4.49 matched cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            }
        ]
        self.assertEqual(_explainability_coverage(findings), 100.0)

    def test_prioritization_quality_rewards_important_findings_at_top(self):
        findings = [
            {
                "cve_id": "CVE-IMPORTANT-1",
                "cvss": 9.8,
                "epss": 0.9,
                "kev": 1,
                "exploit": 1,
            },
            {
                "cve_id": "CVE-IMPORTANT-2",
                "cvss": 8.1,
                "epss": 0.6,
                "kev": 0,
                "exploit": 0,
            },
            {
                "cve_id": "CVE-LOW-1",
                "cvss": 2.1,
                "epss": 0.01,
                "kev": 0,
                "exploit": 0,
            },
        ]
        self.assertEqual(_prioritization_quality(findings), 100.0)

    def test_alert_dedup_rate_drops_when_duplicate_unresolved_alerts_exist(self):
        alerts = [
            _AlertStub("s1", "new_high", "A", "detail"),
            _AlertStub("s1", "new_high", "A", "detail"),
            _AlertStub("s1", "port_change", "B", "detail-2"),
        ]
        self.assertLess(_alert_dedup_rate(alerts), 100.0)


if __name__ == "__main__":
    unittest.main()
