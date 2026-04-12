import unittest

from backend.explainability import explain_finding


class ExplainabilityTests(unittest.TestCase):
    def test_database_service_maps_to_data_risk(self):
        finding = {
            "cve_id": "CVE-TEST-0001",
            "severity": "HIGH",
            "cvss": 8.2,
            "kev": 0,
            "exploit": 0,
            "affected_assets": 1,
            "evidence": "127.0.0.1:3306 mysql 8.0.0 matched cpe:2.3:a:oracle:mysql:8.0.0:*:*:*:*:*:*:*",
        }
        explanation = explain_finding(finding)
        self.assertEqual(explanation["business_impact_label"], "Data Risk")
        self.assertIn("stored information", explanation["business_impact_reason"])

    def test_kev_language_is_explicit(self):
        finding = {
            "cve_id": "CVE-TEST-0002",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "kev": 1,
            "exploit": 1,
            "affected_assets": 1,
            "evidence": "127.0.0.1:8080 apache 2.4.49 matched cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        }
        explanation = explain_finding(finding)
        self.assertIn("Known Exploited Vulnerabilities", explanation["why_it_matters"])
        self.assertIn("escalate this quickly", explanation["recommended_next_step"])


if __name__ == "__main__":
    unittest.main()
